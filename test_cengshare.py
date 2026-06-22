"""
test_cengshare.py — End-to-end self-test of the CENGShare security pipeline.

Covers six security scenarios:

1. Successful secure transfer.
2. Tampered ciphertext rejection.
3. Tampered metadata rejection.
4. Forged sender / wrong signing key rejection.
5. Malformed package rejection.
6. Hash-chained audit-log tamper detection.

Run:
    python3 test_cengshare.py
"""

import base64
import copy
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

import audit_log
from crypto_utils import (
    create_secure_package,
    ensure_keys,
    load_private_key,
    load_public_key,
    open_secure_package,
)

PASS = "PASS ✅"
FAIL = "FAIL ❌"
results = []


def check(name: str, condition: bool) -> None:
    """Record and display the result of one security check."""
    results.append((name, condition))
    print(f"  {PASS if condition else FAIL}  {name}")


# ---------------------------------------------------------------------------
# Load the legitimate CENGShare identities
# ---------------------------------------------------------------------------

keys = ensure_keys()

sender_private = load_private_key(keys["sender_private"])
trusted_sender_public = load_public_key(keys["sender_public"])

receiver_private = load_private_key(keys["receiver_private"])
receiver_public = load_public_key(keys["receiver_public"])


# ---------------------------------------------------------------------------
# Create a legitimate secure package
# ---------------------------------------------------------------------------

data = (
    b"Top secret CENG report: launch codes 0000-1111-2222.\n"
    * 50
)

package = create_secure_package(
    plaintext=data,
    filename="secret.txt",
    sender_private_key=sender_private,
    receiver_public_key=receiver_public,
)


# ---------------------------------------------------------------------------
# 1. Successful secure transfer
# ---------------------------------------------------------------------------

print("\n[1] Successful secure transfer")

result = open_secure_package(
    package,
    receiver_private,
    expected_sender_public_key=trusted_sender_public,
)

check("package valid", result.package_valid)
check("signature valid", result.signature_valid)
check("integrity valid", result.integrity_valid)
check("decrypted", result.decrypted)
check("plaintext round-trips", result.plaintext == data)
check("overall accepted", result.ok)


# ---------------------------------------------------------------------------
# 2. Tampered ciphertext
# ---------------------------------------------------------------------------

print("\n[2] Tampered ciphertext is rejected")

tampered_ciphertext_package = copy.deepcopy(package)

ciphertext_bytes = bytearray(
    base64.b64decode(tampered_ciphertext_package["ciphertext"])
)

# Deliberately modify one encrypted byte.
ciphertext_bytes[10] ^= 0xFF

tampered_ciphertext_package["ciphertext"] = base64.b64encode(
    bytes(ciphertext_bytes)
).decode("utf-8")

tampered_result = open_secure_package(
    tampered_ciphertext_package,
    receiver_private,
    expected_sender_public_key=trusted_sender_public,
)

check(
    "tampered package remains structurally readable",
    tampered_result.package_valid,
)
check(
    "tampered ciphertext signature rejected",
    not tampered_result.signature_valid,
)
check(
    "tampered ciphertext decryption blocked",
    not tampered_result.decrypted,
)
check(
    "tampered ciphertext plaintext not exposed",
    tampered_result.plaintext is None,
)
check(
    "tampered ciphertext package rejected",
    not tampered_result.ok,
)


# ---------------------------------------------------------------------------
# 3. Tampered metadata
# ---------------------------------------------------------------------------

print("\n[3] Tampered metadata is rejected")

metadata_tampered_package = copy.deepcopy(package)

# Simulate an attacker changing the original filename.
metadata_tampered_package["metadata"]["filename"] = "malicious_file.exe"

metadata_result = open_secure_package(
    metadata_tampered_package,
    receiver_private,
    expected_sender_public_key=trusted_sender_public,
)

check(
    "metadata-tampered package remains structurally readable",
    metadata_result.package_valid,
)
check(
    "metadata signature rejected",
    not metadata_result.signature_valid,
)
check(
    "metadata decryption blocked",
    not metadata_result.decrypted,
)
check(
    "metadata plaintext not exposed",
    metadata_result.plaintext is None,
)
check(
    "metadata-tampered package rejected",
    not metadata_result.ok,
)


# ---------------------------------------------------------------------------
# 4. Forged sender
# ---------------------------------------------------------------------------

print("\n[4] Forged sender is rejected")

attacker_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

forged_package = create_secure_package(
    plaintext=data,
    filename="secret.txt",
    sender_private_key=attacker_private,
    receiver_public_key=receiver_public,
)

forged_result = open_secure_package(
    forged_package,
    receiver_private,
    expected_sender_public_key=trusted_sender_public,
)

check(
    "forged package structurally valid",
    forged_result.package_valid,
)
check(
    "forged sender signature rejected",
    not forged_result.signature_valid,
)
check(
    "forged package decryption blocked",
    not forged_result.decrypted,
)
check(
    "forged package plaintext not exposed",
    forged_result.plaintext is None,
)
check(
    "forged package rejected",
    not forged_result.ok,
)


# ---------------------------------------------------------------------------
# 5. Malformed package
# ---------------------------------------------------------------------------

print("\n[5] Malformed package is rejected")

malformed_result = open_secure_package(
    {"version": "1.0"},
    receiver_private,
    expected_sender_public_key=trusted_sender_public,
)

check(
    "malformed package marked invalid",
    not malformed_result.package_valid,
)
check(
    "malformed package not decrypted",
    not malformed_result.decrypted,
)
check(
    "malformed package plaintext not exposed",
    malformed_result.plaintext is None,
)
check(
    "malformed package rejected",
    not malformed_result.ok,
)


# ---------------------------------------------------------------------------
# 6. Audit-log hash-chain tampering
# ---------------------------------------------------------------------------

print("\n[6] Audit-log hash chain")

# Use a temporary audit file so the self-test does not modify the real
# demonstration audit log.
original_audit_path = audit_log.AUDIT_PATH

with tempfile.TemporaryDirectory() as temporary_directory:
    audit_log.AUDIT_PATH = (
        Path(temporary_directory) / "test_audit_log.jsonl"
    )

    try:
        audit_log.log_event(
            "TEST_PACKAGE_CREATED",
            {
                "scenario": "self-test",
                "status": "success",
            },
        )

        audit_log.log_event(
            "TEST_PACKAGE_VERIFIED",
            {
                "scenario": "self-test",
                "status": "success",
            },
        )

        intact_chain = audit_log.verify_chain()

        check(
            "audit chain intact after valid events",
            intact_chain["intact"],
        )

        # Deliberately change the first event without recalculating its hash.
        audit_lines = audit_log.AUDIT_PATH.read_text(
            encoding="utf-8"
        ).splitlines()

        first_record = json.loads(audit_lines[0])
        first_record["details"]["status"] = "tampered"

        audit_lines[0] = json.dumps(first_record)

        audit_log.AUDIT_PATH.write_text(
            "\n".join(audit_lines) + "\n",
            encoding="utf-8",
        )

        broken_chain = audit_log.verify_chain()

        check(
            "audit tampering detected",
            not broken_chain["intact"],
        )

        check(
            "first damaged audit record identified",
            broken_chain["broken_index"] == 0,
        )

    finally:
        # Restore the real application audit-log path.
        audit_log.AUDIT_PATH = original_audit_path


# ---------------------------------------------------------------------------
# Final result
# ---------------------------------------------------------------------------

print("\n" + "=" * 58)

passed = sum(
    1
    for _, condition in results
    if condition
)

total = len(results)

print(f"  {passed}/{total} security checks passed")
print("=" * 58)

raise SystemExit(
    0 if passed == total else 1
)
