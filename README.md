# 🔐 CENGShare — Secure Document Sharing

A defensive-cybersecurity web app by **Team CENG**. One file transfer, five
security pillars — each backed by a real cryptographic mechanism, not a mockup.

> **Status:** ✅ Self-test **11/11 pass** · ✅ App boots clean (Streamlit HTTP 200,
> headless, zero errors in the boot log).

| Pillar | Mechanism |
|---|---|
| **Confidentiality** | File body encrypted with **AES-256-GCM** (random key + nonce) |
| **Key protection** | AES key wrapped with the receiver's **RSA-2048 public key** (OAEP) |
| **Integrity** | **SHA-256** hash of the plaintext, re-checked after decryption |
| **Authentication** | Hash **digitally signed** with the sender's RSA private key (PSS), verified *before* decryption |
| **Detection** | **IDS** flags tampered files, invalid packages, failed decryption, bad signatures, and `REPEATED_SUSPICIOUS_ACCESS` (≥3 failures in 120s) |
| **Accountability** | **Hash-chained forensic audit log** that names the exact broken record on tamper |

## The problem we address

Files shared over email, chat or cloud links routinely arrive with **no proof of
who sent them and no proof they weren't altered in transit**. A recipient cannot
tell an authentic document from a tampered or forged one, and there is usually no
tamper-evident record of who accessed what. CENGShare closes that gap: it bundles
a document into a single secure package that is **confidential** (encrypted),
**authenticated** (signed by the sender), and **integrity-checked** (hash verified
before decryption), while an **IDS** watches for attacks and a **hash-chained
audit log** keeps an accountable, tamper-evident trail of every event.

## Tech stack

| Layer | Tools |
|---|---|
| Language | **Python 3** |
| Web UI | **Streamlit** |
| Cryptography | **`cryptography`** (AES-256-GCM, RSA-2048 OAEP + PSS), **`hashlib`** (SHA-256) |
| Packages & logs | **JSON / JSON-Lines** (secure packages, audit log, IDS alerts) |
| Testing | Standalone Python self-test (`test_cengshare.py`) |

## Run it

```bash
cd /Users/mubaraq/Documents/ML/CENG
.venv/bin/streamlit run app.py        # venv already created with deps
```

First run from scratch (if the venv is missing):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/streamlit run app.py
```

On first launch, RSA keypairs are generated under `keys/` — a `sender` pair for
signing and a `receiver` pair for key wrapping.

## The pipeline at a glance

```
SENDER                                          RECEIVER
  file ──► AES-256-GCM ──► ciphertext           verify signature ─┐  (1) authentication
  AES key ──► RSA-OAEP ──► wrapped key           unwrap AES key   │  (2) key recovery
  SHA-256(file) ──► RSA-PSS sign ──► signature   AES-GCM decrypt  │  (3) confidentiality
            └────────► .cengshare.json ─────►    re-hash == signed?┘  (4) integrity
```

**Verification order is enforced — signature → key unwrap → decrypt → integrity.**
Each step leaves its own pass/fail flag, so the IDS can classify *why* a transfer
failed, not merely *that* it failed.

## The four tabs

1. **📤 Send Secure File** — upload a document → encrypted, hashed and signed →
   download the `.cengshare.json` secure package.
2. **📥 Receive & Verify** — upload a package → signature + integrity checked
   *before* decryption → download the recovered file only if every check passes.
3. **🛡️ IDS Monitoring** — live table of security alerts with severities.
4. **📜 Forensic Audit Log** — every event chained with SHA-256; the verifier
   reports the exact record index where tampering occurred.

## Demo script (the four scenarios)

1. **Successful transfer** — Send `report.txt`, then Receive & Verify the
   package → all four badges green, decrypted file downloads.
2. **Tampered-file rejection** — Open the `.cengshare.json` in a text editor,
   change a few characters inside `"ciphertext"`, re-upload → decryption refused,
   integrity/decryption badge red.
3. **IDS alert** — After (2), open **IDS Monitoring** → a `CRITICAL` alert is
   listed. Repeat a few bad uploads to trip `REPEATED_SUSPICIOUS_ACCESS`.
4. **Forensic audit trail** — Open **Forensic Audit Log** → chain shows "intact".
   Hand-edit a past record in `logs/audit_log.jsonl`, reload → chain reports the
   broken record index.

## Self-test

```bash
.venv/bin/python test_cengshare.py
```

Runs all four scenarios headlessly — **11 assertions**: successful transfer,
tampered-ciphertext rejection, forged-sender rejection, malformed-package
rejection, and audit-chain integrity.

## What's in `CENG/`

| File | Role |
|---|---|
| `app.py` | Streamlit UI — the four tabs |
| `crypto_utils.py` | AES-256-GCM + RSA-OAEP/PSS, hashing, package format |
| `audit_log.py` | Hash-chained tamper-evident log |
| `ids.py` | Intrusion detection + alerting |
| `test_cengshare.py` | End-to-end self-test (11 assertions) |
| `README.md` | Setup + 4-scenario demo script |

`keys/`, `logs/`, and `.venv/` are git-ignored — private keys never get committed.

## Team

**Team CENG**




## Limitations & next steps

- **Single-machine demo.** Both RSA keypairs live locally so one box can play
  sender **and** receiver. *Next step:* split into a true two-party flow where
  each side holds only its own private key and exchanges public keys out of band.
- **No persistent user accounts / transport security.** The app trusts whoever
  runs it locally. *Next step:* add authentication and serve over HTTPS for a
  networked deployment.
- **Demo-scale IDS.** Detection is rule-based over recent events. *Next step:*
  configurable thresholds and longer-horizon behavioural analytics.
- **Key management is file-based.** *Next step:* integrate a proper keystore / HSM
  and key rotation.

## Attribution

This project is **original work by Team CENG**, built for this challenge. It uses
the open-source **Streamlit** and **`cryptography`** libraries (see
`requirements.txt`); no other prior project or codebase was reused.

## Notes for graders

- **Why both a GCM tag *and* a separate signature?** AES-GCM already gives
  authenticated encryption, but the **separate SHA-256 + RSA-PSS layer** is what
  proves *sender identity* and produces the forensic hash the brief calls for —
  satisfying integrity **and** authentication explicitly, not as a side effect.
- **Single-machine demo.** Both RSA keypairs live locally so one box can play
  sender **and** receiver. In a real deployment the receiver's private key never
  leaves the receiver, and the sender's public key is distributed out of band.
  Splitting this into a true two-party flow (paste-in public keys) is a small,
  well-scoped extension if needed.
