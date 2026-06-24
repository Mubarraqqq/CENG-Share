
from __future__ import annotations

import json

import streamlit as st

import audit_log
import channel
import identity
import ids
from crypto_utils import (
    create_secure_package,
    open_secure_package,
    package_from_bytes,
    package_to_bytes,
)

st.set_page_config(page_title="CENGShare", page_icon="", layout="wide")


def _badge(ok: bool, label: str) -> str:
    return f"{'good' if ok else 'issue'} {label}"


def verify_and_report(package: dict, source: str, *, dl_key: str):
    """Verify a parsed package, log it, raise IDS alerts and render the report.

    Shared by the inbox flow and the manual upload flow so a tampered package
    is judged by exactly the same checks regardless of how it arrived.
    Returns the VerificationResult.
    """
    claimed_sender = package.get("metadata", {}).get("sender", "?")
    trusted_pub = identity.get_public_key(claimed_sender)
    sender_known = trusted_pub is not None

    if not sender_known:
        ids.raise_alert(
            "WARNING",
            "UNKNOWN_SENDER",
            f"Sender '{claimed_sender}' is not in the trusted keyring.",
            {"source": source},
        )

        audit_log.log_event(
            "VERIFY_FAIL",
            {
                "source": source,
                "claimed_sender": claimed_sender,
                "reason": "unknown sender",
            },
        )

        st.error(
            f"Sender '{claimed_sender}' is not trusted. "
            "Signature verification and decryption were blocked."
        )

        return None

    # Impersonation check: the embedded key must match the trusted one.
    embedded = (package.get("sender_public_key") or "").strip()
    trusted_pem = (identity.public_pem(claimed_sender) or "").strip()
    key_mismatch = sender_known and embedded != trusted_pem

    receiver_private = identity.get_private_key(me)
    result = open_secure_package(
        package, receiver_private, expected_sender_public_key=trusted_pub
    )
    audit_log.log_event(
        "VERIFY",
        {"source": source, "claimed_sender": claimed_sender,
         "sender_known": sender_known, **result.as_dict()},
    )
    alerts = ids.analyze_verification(result, source=source)


    if key_mismatch:
        alerts.append(ids.raise_alert(
            "CRITICAL", "SENDER_KEY_MISMATCH",
            f"Embedded key does not match the trusted key for '{claimed_sender}' — possible impersonation.",
            {"source": source}))

    st.markdown("#### Verification report")
    if sender_known and result.signature_valid:
        st.success(f"Verified sender: **{claimed_sender}** · `{identity.fingerprint(claimed_sender)}`")
    elif not sender_known:
        st.warning(f"Sender '{claimed_sender}' is not in your keyring — identity could not be verified.")

    c1, c2, c3, c4 = st.columns(4)
    c1.write(_badge(result.package_valid, "Package valid"))
    c2.write(_badge(result.signature_valid, "Signature"))
    c3.write(_badge(result.integrity_valid, "Integrity"))
    c4.write(_badge(result.decrypted, "Decrypted"))

    if result.ok:
        st.success("All checks passed — file authentic and intact.")
        audit_log.log_event("DECRYPT", {"source": source, "filename": result.filename})
        st.download_button(
            "⬇️ Download Decrypted File",
            data=result.plaintext,
            file_name=result.filename or "recovered.bin",
            key=dl_key,
        )
    else:
        st.error("Verification failed — decryption refused.")
        for err in result.errors:
            st.write(f"- {err}")
        if alerts:
            st.warning(f"{len(alerts)} IDS alert(s) raised. See the IDS Monitoring tab.")
    return result


# --------------------------------------------------------------------------- #
# Sidebar — who am I?
# --------------------------------------------------------------------------- #
st.sidebar.header("Your identity")
identities = identity.list_identities()

# Two-party setup: name the sender and the receiver, then create both keypairs.
with st.sidebar.expander("Set up the two users", expanded=len(identities) < 2):
    sender_name = st.text_input("Sender name", placeholder="e.g. Alice", key="setup_sender")
    receiver_name = st.text_input("Receiver name", placeholder="e.g. Bob", key="setup_receiver")
    if st.button("Create users", type="primary", key="setup_create"):
        names = [sender_name.strip(), receiver_name.strip()]
        if not all(names):
            st.error("Enter a name for both the sender and the receiver.")
        elif names[0] == names[1]:
            st.error("Sender and receiver must have different names.")
        else:
            for nm in names:
                identity.create_identity(nm)
            audit_log.log_event(
                "IDENTITY_CREATE", {"sender": names[0], "receiver": names[1]}
            )
            st.rerun()

if not identities:
    st.title("🔐 CENGShare")
    st.info(
        "Name the two users — one **sender**, one **receiver** — in the sidebar to "
        "begin. Then open a second browser tab and act as the other one. Their "
        "public keys are shared automatically via the channel."
    )
    st.stop()

me = st.sidebar.selectbox("Acting as", identities, key="identity_choice")
st.sidebar.success(f"You are **{me}**")
fp = identity.fingerprint(me)
if fp:
    st.sidebar.caption(f"Key fingerprint · `{fp}`")

contacts = [c for c in identity.list_contacts() if c != me]
st.sidebar.markdown("**Contacts on the channel**")
if contacts:
    for c in contacts:
        st.sidebar.caption(f"• {c} · `{identity.fingerprint(c)}`")
else:
    st.sidebar.caption("_None yet — create another identity._")


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
st.title(" CENGShare")
st.caption(
    "Secure document sharing · Confidentiality · Integrity · Authentication · "
    "Detection · Accountability — by Team CENG"
)

tab_send, tab_receive, tab_ids, tab_audit = st.tabs(
    [" Send Secure File", "Receive & Verify", " IDS Monitoring", " Forensic Audit Log"]
)

# --------------------------------------------------------------------------- #
# Tab 1 — Send Secure File
# --------------------------------------------------------------------------- #
with tab_send:
    st.subheader(f"Send a Secure File — as {me}")
    st.write(
        "The file is encrypted with **AES-256-GCM**. The AES key is wrapped with "
        "the **recipient's RSA public key** (from the channel keyring). The file "
        "is **hashed (SHA-256)** and the hash is **signed** with your private key."
    )

    if not contacts:
        st.info(
            "No other identities are on the channel yet. Create a second identity "
            "(e.g. Bob) from the sidebar, or have your teammate create theirs — it "
            "will appear here automatically."
        )
    else:
        recipient = st.selectbox("Send to", contacts, key="send_to")
        upload = st.file_uploader("Choose a document to protect", key="send_upload")
        if upload is not None:
            plaintext = upload.read()
            st.info(f"Loaded **{upload.name}** ({len(plaintext):,} bytes).")

            if st.button("🔒 Encrypt, Sign & Send to channel", type="primary"):
                sender_private = identity.get_private_key(me)
                recipient_public = identity.get_public_key(recipient)
                package = create_secure_package(
                    plaintext, upload.name, sender_private, recipient_public,
                    sender_name=me, recipient_name=recipient,
                )
                pkg_bytes = package_to_bytes(package)
                msg_id = channel.publish(pkg_bytes, me, recipient)
                audit_log.log_event(
                    "ENCRYPT",
                    {"filename": upload.name, "size": len(plaintext),
                     "file_hash": package["file_hash"], "sender": me, "recipient": recipient},
                )
                audit_log.log_event(
                    "SEND", {"msg_id": msg_id, "from": me, "to": recipient,
                             "filename": upload.name},
                )

                st.success(f"Sent to **{recipient}** through the channel.")
                c1, c2, c3 = st.columns(3)
                c1.metric("AES", "256-bit GCM")
                c2.metric("Key wrap", "RSA-OAEP 2048")
                c3.metric("Signature", "RSA-PSS")

                with st.expander("Package details"):
                    st.write(f"**Message id:** `{msg_id}`")
                    st.write(f"**SHA-256:** `{package['file_hash']}`")
                    st.write(f"**Signature (b64, head):** `{package['signature'][:60]}…`")
                    st.json(package["metadata"])

                st.download_button(
                    "⬇️ Download package (optional backup copy)",
                    data=pkg_bytes,
                    file_name=f"{upload.name}.cengshare.json",
                    mime="application/json",
                )
                st.caption(
                    f"Now switch to the **{recipient}** session and open the "
                    "**Receive & Verify** tab to collect it."
                )

# --------------------------------------------------------------------------- #
# Tab 2 — Receive & Verify
# --------------------------------------------------------------------------- #
with tab_receive:
    st.subheader(f"Receive & Verify — as {me}")
    st.write(
        "Packages addressed to you arrive through the channel. CENGShare verifies "
        "the **sender's signature against your trusted keyring** and the "
        "**integrity hash** before decrypting. Any failure refuses decryption and "
        "alerts the IDS."
    )

    inbox = channel.inbox(me)
    if not inbox:
        st.info("Your inbox is empty. Have another identity send you a file.")
    else:
        labels = {
            f"{m['filename']}  ·  from {m['sender']}  ·  {m['timestamp'][:19].replace('T', ' ')}":
            m["msg_id"]
            for m in inbox
        }
        picked = st.selectbox("Inbox", list(labels.keys()), key="inbox_pick")
        msg_id = labels[picked]

        if st.button("🔎 Verify & Decrypt", type="primary"):
            try:
                package = package_from_bytes(channel.read_package(msg_id))
                parse_error = None
            except Exception as exc:  # noqa: BLE001
                package, parse_error = None, str(exc)

            if parse_error:
                st.error(f"Could not parse package: {parse_error}")
                ids.raise_alert("CRITICAL", "INVALID_PACKAGE",
                                "Package on the channel is not valid JSON.", {"msg_id": msg_id})
                audit_log.log_event("VERIFY_FAIL", {"reason": "unparseable package"})
            else:
                result = verify_and_report(package, msg_id, dl_key=f"dl_inbox_{msg_id}")
                if (
                        result is not None
                        and result.ok
                        and st.button("🗑️ Remove from channel")
                ):
                    channel.delete(msg_id)
                    audit_log.log_event(
                        "CHANNEL_DELETE",
                        {"msg_id": msg_id},
                    )
                    st.rerun()
                    channel.delete(msg_id)
                    audit_log.log_event("CHANNEL_DELETE", {"msg_id": msg_id})
                    st.rerun()

    # ----------------------------------------------------------------------- #
    # Manual upload — drop in a (possibly tampered) package to exercise the IDS
    # ----------------------------------------------------------------------- #
    st.divider()
    st.markdown("#### 🧪 Manually upload a package (IDS demo)")
    st.caption(
        "Upload a `.cengshare.json` package directly — including a **tampered** one "
        "(edit the ciphertext, hash, signature or sender key by hand first). The "
        "same verification runs, so you can watch the IDS flag the forgery."
    )
    pkg_file = st.file_uploader(
        "Upload package to verify", type=["json"], key="manual_pkg_upload"
    )
    if pkg_file is not None and st.button("🔎 Verify uploaded package", key="verify_upload"):
        raw = pkg_file.read()
        try:
            package = package_from_bytes(raw)
            parse_error = None
        except Exception as exc:  # noqa: BLE001
            package, parse_error = None, str(exc)

        if parse_error:
            st.error(f"Could not parse package: {parse_error}")
            ids.raise_alert("CRITICAL", "INVALID_PACKAGE",
                            "Uploaded package is not valid JSON.", {"source": pkg_file.name})
            audit_log.log_event("VERIFY_FAIL",
                                {"source": pkg_file.name, "reason": "unparseable package"})
        else:
            verify_and_report(package, pkg_file.name, dl_key=f"dl_upload_{pkg_file.name}")

# --------------------------------------------------------------------------- #
# Tab 3 — IDS Monitoring
# --------------------------------------------------------------------------- #
with tab_ids:
    st.subheader("Intrusion Detection")
    summary = ids.alert_summary()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", summary["total"])
    c2.metric("Critical", summary.get("CRITICAL", 0))
    c3.metric("Warning", summary.get("WARNING", 0))
    c4.metric("Info", summary.get("INFO", 0))

    st.caption(
        "Detects: tampered files · invalid packages · failed decryption · "
        "bad signatures · unknown sender · repeated suspicious access."
    )

    alerts = list(reversed(ids.read_alerts()))
    if not alerts:
        st.info("No alerts yet. Try tampering with a package on the channel.")
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

    with st.expander("Channel contents (the wire)"):
        wire = channel.all_messages()
        if not wire:
            st.caption("Channel outbox is empty.")
        else:
            st.dataframe(
                [{"msg_id": w["msg_id"], "from": w["sender"], "to": w["recipient"],
                  "file": w["filename"], "corrupt": w["corrupt"]} for w in wire],
                use_container_width=True, hide_index=True,
            )
            st.caption(
                "Tamper test: edit any file in `channel/outbox/`, then Verify it "
                "in the recipient's Receive tab — the IDS will flag it."
            )

# --------------------------------------------------------------------------- #
# Tab 4 — Forensic Audit Log
# --------------------------------------------------------------------------- #
with tab_audit:
    st.subheader(" Forensic Audit Log (hash-chained)")
    st.write(
        "Every event is chained to the previous one with SHA-256. Altering any "
        "past record breaks the chain — proving tamper-evidence."
    )

    chain = audit_log.verify_chain()
    if chain["intact"]:
        st.success(f" Chain intact — {chain['count']} record(s) verified.")
    else:
        st.error(
            f" Chain BROKEN at record #{chain['broken_index']}: {chain['reason']}"
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

    with st.expander(" Tamper test (for the demo)"):
        st.write(
            "Edit `logs/audit_log.jsonl` by hand (change any past record), then "
            "reopen this tab — the chain check above will report the broken index."
        )
        