"""
CENGShare — Secure Document Sharing (Team CENG)

A defensive-cybersecurity demo covering the five pillars:
  Confidentiality (AES-256-GCM), Integrity (SHA-256), Authentication (RSA-PSS
  signatures), Detection (IDS), and Accountability (hash-chained audit log).

Run:  streamlit run app.py
"""

from __future__ import annotations

import json

import streamlit as st

import audit_log
import ids
from crypto_utils import (
    create_secure_package,
    ensure_keys,
    load_private_key,
    load_public_key,
    open_secure_package,
    package_from_bytes,
    package_to_bytes,
)

st.set_page_config(page_title="CENGShare", page_icon="🔐", layout="wide")

# Ensure RSA keypairs exist for the demo (sender signs, receiver unwraps key).
KEYS = ensure_keys()


def _badge(ok: bool, label: str) -> str:
    return f"{'✅' if ok else '❌'} {label}"


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
st.title("🔐 CENGShare")
st.caption(
    "Secure document sharing · Confidentiality · Integrity · Authentication · "
    "Detection · Accountability — by Team CENG"
)

tab_send, tab_receive, tab_ids, tab_audit = st.tabs(
    ["📤 Send Secure File", "📥 Receive & Verify", "🛡️ IDS Monitoring", "📜 Forensic Audit Log"]
)

# --------------------------------------------------------------------------- #
# Tab 1 — Send Secure File
# --------------------------------------------------------------------------- #
with tab_send:
    st.subheader("Send a Secure File")
    st.write(
        "The file is encrypted with **AES-256-GCM**. The AES key is wrapped with "
        "the receiver's **RSA public key**. The file is **hashed (SHA-256)** and "
        "the hash is **digitally signed** with the sender's RSA private key."
    )

    upload = st.file_uploader("Choose a document to protect", key="send_upload")
    if upload is not None:
        plaintext = upload.read()
        st.info(f"Loaded **{upload.name}** ({len(plaintext):,} bytes).")

        if st.button("🔒 Encrypt, Hash & Sign", type="primary"):
            sender_private = load_private_key(KEYS["sender_private"])
            receiver_public = load_public_key(KEYS["receiver_public"])
            package = create_secure_package(
                plaintext, upload.name, sender_private, receiver_public
            )
            audit_log.log_event(
                "ENCRYPT",
                {"filename": upload.name, "size": len(plaintext),
                 "file_hash": package["file_hash"]},
            )

            st.success("Secure package created.")
            c1, c2, c3 = st.columns(3)
            c1.metric("AES", "256-bit GCM")
            c2.metric("Key wrap", "RSA-OAEP 2048")
            c3.metric("Signature", "RSA-PSS")

            with st.expander("Package details"):
                st.write(f"**SHA-256:** `{package['file_hash']}`")
                st.write(f"**Signature (b64, head):** `{package['signature'][:60]}…`")
                st.json(package["metadata"])

            package_bytes = package_to_bytes(package)
            out_name = f"{upload.name}.cengshare.json"
            st.download_button(
                "⬇️ Download Secure Package",
                data=package_bytes,
                file_name=out_name,
                mime="application/json",
            )
            st.caption(
                "Hand this `.cengshare.json` package to the receiver and open it "
                "in the **Receive & Verify** tab."
            )

# --------------------------------------------------------------------------- #
# Tab 2 — Receive & Verify
# --------------------------------------------------------------------------- #
with tab_receive:
    st.subheader("Receive & Verify")
    st.write(
        "Upload a secure package. CENGShare verifies the **signature** and "
        "**integrity hash** before decrypting. If any check fails, decryption is "
        "refused and the IDS is alerted."
    )

    pkg_file = st.file_uploader(
        "Upload a .cengshare.json package", type=["json"], key="recv_upload"
    )
    if pkg_file is not None:
        try:
            package = package_from_bytes(pkg_file.read())
            parse_error = None
        except Exception as exc:  # noqa: BLE001
            package, parse_error = None, str(exc)

        if parse_error:
            st.error(f"Could not parse package: {parse_error}")
            ids.raise_alert("CRITICAL", "INVALID_PACKAGE",
                            "Uploaded package is not valid JSON.", {"source": pkg_file.name})
            audit_log.log_event("VERIFY_FAIL", {"reason": "unparseable package"})
        else:
            receiver_private = load_private_key(KEYS["receiver_private"])
            result = open_secure_package(package, receiver_private)

            audit_log.log_event(
                "VERIFY",
                {"filename": result.filename, **result.as_dict()},
            )
            alerts = ids.analyze_verification(result, source=pkg_file.name)

            st.markdown("#### Verification report")
            c1, c2, c3, c4 = st.columns(4)
            c1.write(_badge(result.package_valid, "Package valid"))
            c2.write(_badge(result.signature_valid, "Signature"))
            c3.write(_badge(result.integrity_valid, "Integrity"))
            c4.write(_badge(result.decrypted, "Decrypted"))

            if result.ok:
                st.success("All checks passed — file authentic and intact.")
                audit_log.log_event("DECRYPT", {"filename": result.filename})
                st.download_button(
                    "⬇️ Download Decrypted File",
                    data=result.plaintext,
                    file_name=result.filename or "recovered.bin",
                )
            else:
                st.error("Verification failed — decryption refused.")
                for err in result.errors:
                    st.write(f"- ⚠️ {err}")
                if alerts:
                    st.warning(f"🛡️ {len(alerts)} IDS alert(s) raised. See the IDS Monitoring tab.")

# --------------------------------------------------------------------------- #
# Tab 3 — IDS Monitoring
# --------------------------------------------------------------------------- #
with tab_ids:
    st.subheader("🛡️ Intrusion Detection")
    summary = ids.alert_summary()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", summary["total"])
    c2.metric("Critical", summary.get("CRITICAL", 0))
    c3.metric("Warning", summary.get("WARNING", 0))
    c4.metric("Info", summary.get("INFO", 0))

    st.caption(
        "Detects: tampered files · invalid packages · failed decryption · "
        "bad signatures · repeated suspicious access."
    )

    alerts = list(reversed(ids.read_alerts()))
    if not alerts:
        st.info("No alerts yet. Try uploading a tampered package in Receive & Verify.")
    else:
        rows = [
            {
                "time": a["timestamp"].replace("T", " ")[:19],
                "severity": a["severity"],
                "category": a["category"],
                "message": a["message"],
            }
            for a in alerts
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)

# --------------------------------------------------------------------------- #
# Tab 4 — Forensic Audit Log
# --------------------------------------------------------------------------- #
with tab_audit:
    st.subheader("📜 Forensic Audit Log (hash-chained)")
    st.write(
        "Every event is chained to the previous one with SHA-256. Altering any "
        "past record breaks the chain — proving tamper-evidence."
    )

    chain = audit_log.verify_chain()
    if chain["intact"]:
        st.success(f"✅ Chain intact — {chain['count']} record(s) verified.")
    else:
        st.error(
            f"❌ Chain BROKEN at record #{chain['broken_index']}: {chain['reason']}"
        )

    records = list(reversed(audit_log.read_log()))
    if not records:
        st.info("No events logged yet.")
    else:
        rows = [
            {
                "#": r["index"],
                "time": r["timestamp"].replace("T", " ")[:19],
                "event": r["event"],
                "details": json.dumps(r["details"]),
                "entry_hash": r["entry_hash"][:16] + "…",
            }
            for r in records
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)

    with st.expander("🔬 Tamper test (for the demo)"):
        st.write(
            "Edit `logs/audit_log.jsonl` by hand (change any past record), then "
            "reopen this tab — the chain check above will report the broken index."
        )
