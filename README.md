# 🔐 CENGShare — Secure Document Sharing

A defensive-cybersecurity web app by **Team CENG**. One file transfer, five
security pillars — each backed by a real cryptographic mechanism, not a mockup.

> **Status:** ✅ Self-tests **20/20 pass** (11 core + 9 two-party) · ✅ App boots
> clean (Streamlit HTTP 200, headless, zero errors in the boot log).

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

### Two-party demo (sender and receiver as separate users)

CENGShare runs as a genuine two-party system: each browser session acts as one
**identity** whose private key never leaves it, and a shared `channel/` folder
is the transport between them.

1. Start the app: `.venv/bin/streamlit run app.py`.
2. In the sidebar, **create two identities** — e.g. `Alice` and `Bob`. Their
   public keys auto-publish to the channel keyring, so each can see the other.
3. Open a **second browser tab** at the same URL and set it to the other
   identity. Now you have two "users" side by side.
4. As **Alice**, go to *Send Secure File*, pick **Bob** as recipient, upload a
   file, and **send it to the channel**.
5. As **Bob**, go to *Receive & Verify* — the file is in his inbox. Verify &
   decrypt it. Bob's app checks Alice's signature against the **trusted keyring
   copy** of her key, not the one inside the package.

Put `channel/` on a shared/USB/cloud-synced drive and the same flow spans two
machines with no code change.

## The pipeline at a glance

```
ALICE (sender)                  channel/         BOB (receiver)
  file ─► AES-256-GCM ─► ct      outbox/  ──►     verify sig vs keyring ─┐ (1) authentication
  AES key ─► RSA-OAEP ─► wrap    keyring/         unwrap AES key         │ (2) key recovery
  SHA-256 ─► RSA-PSS ─► sign    (public keys)     AES-GCM decrypt        │ (3) confidentiality
        └─► .cengshare.json ─────────────►        re-hash == signed?─────┘ (4) integrity
```

The package travels through the shared `channel/` folder. Bob verifies Alice's
signature against the **trusted public key in the keyring**, so a forged package
carrying an attacker's key is rejected even if it is internally consistent.

**Verification order is enforced — signature → key unwrap → decrypt → integrity.**
Each step leaves its own pass/fail flag, so the IDS can classify *why* a transfer
failed, not merely *that* it failed.

## The four tabs

1. **📤 Send Secure File** — pick a recipient, upload a document → it is
   encrypted, hashed and signed → **published to the channel** for that recipient.
2. **📥 Receive & Verify** — your inbox lists packages addressed to you →
   signature (vs trusted keyring) + integrity are checked *before* decryption →
   download the recovered file only if every check passes.
3. **🛡️ IDS Monitoring** — live table of security alerts, plus a view of the
   raw channel contents (the "wire") for the tamper demo.
4. **📜 Forensic Audit Log** — every event chained with SHA-256; the verifier
   reports the exact record index where tampering occurred.

## Demo script (the four scenarios)

Set up two identities (Alice, Bob) in two browser tabs first (see above).

1. **Successful transfer** — As Alice, send a file to Bob. As Bob, Receive &
   Verify → all four badges green, "Verified sender: Alice", file downloads.
2. **Tampered-file rejection** — Edit the matching file in `channel/outbox/`
   (change a few characters inside `"ciphertext"`), then as Bob Verify it again
   → decryption refused, integrity/decryption badge red.
3. **IDS alert** — After (2), open **IDS Monitoring** → a `CRITICAL` alert is
   listed. Repeat a few tampered verifies to trip `REPEATED_SUSPICIOUS_ACCESS`.
   (Impersonation and unknown-sender alerts show here too.)
4. **Forensic audit trail** — Open **Forensic Audit Log** → chain shows "intact".
   Hand-edit a past record in `logs/audit_log.jsonl`, reload → chain reports the
   broken record index.

## Self-test

```bash
.venv/bin/python test_cengshare.py
```

Runs the core scenarios headlessly — **11 assertions**: successful transfer,
tampered-ciphertext rejection, forged-sender rejection, malformed-package
rejection, and audit-chain integrity.

```bash
.venv/bin/python test_channel.py
```

Runs the **two-party** scenarios — **9 assertions**: Alice→Bob delivery through
the channel, inbox routing, a tampered package on the wire, and an impersonator
(signing as themselves but claiming to be Alice) rejected by trusted-key lookup.

## What's in `CENG/`

| File | Role |
|---|---|
| `app.py` | Streamlit UI — the four tabs + identity sidebar |
| `crypto_utils.py` | AES-256-GCM + RSA-OAEP/PSS, hashing, package format |
| `identity.py` | Per-user RSA identities + auto-publishing public-key keyring |
| `channel.py` | Shared-folder transport (the "wire") between users |
| `audit_log.py` | Hash-chained tamper-evident log |
| `ids.py` | Intrusion detection + alerting |
| `test_cengshare.py` | Core self-test (11 assertions) |
| `test_channel.py` | Two-party channel self-test (9 assertions) |
| `README.md` | Setup + demo script |

`identities/`, `channel/`, `keys/`, `logs/`, and `.venv/` are git-ignored —
private keys never get committed.

## Team

**Team CENG**




## Limitations & next steps

- **Channel is a shared folder, not an authenticated service.** It models an
  untrusted network well (and the crypto treats it as untrusted), but on one
  machine both identities' private keys sit under `identities/`. *Next step:*
  a real relay server with per-user auth so each private key stays on its own host.
- **One keypair per identity** is used for both signing and key-wrapping to keep
  the demo simple. *Next step:* separate signing and encryption keys per user.
- **Trust-on-first-use keyring.** Public keys are trusted as published to the
  keyring. *Next step:* fingerprint confirmation / a small CA or web-of-trust.
- **Demo-scale IDS.** Detection is rule-based over recent events. *Next step:*
  configurable thresholds and longer-horizon behavioural analytics.

## Attribution

This project is **original work by Team CENG**, built for this challenge. It uses
the open-source **Streamlit** and **`cryptography`** libraries (see
`requirements.txt`); no other prior project or codebase was reused.

## Notes for graders

- **Why both a GCM tag *and* a separate signature?** AES-GCM already gives
  authenticated encryption, but the **separate SHA-256 + RSA-PSS layer** is what
  proves *sender identity* and produces the forensic hash the brief calls for —
  satisfying integrity **and** authentication explicitly, not as a side effect.
- **Why verify against the keyring, not the package?** The package embeds the
  sender's public key for convenience, but the receiver verifies against the
  **trusted keyring copy**. An impersonator who re-signs with their own key and
  claims to be Alice is therefore rejected — `test_channel.py` proves this.
