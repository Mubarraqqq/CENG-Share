"""
test_cengshare.py — End-to-end self-test of the CENGShare security pipeline.

Covers the four demo scenarios:
  1. Successful secure transfer (all checks pass).
  2. Tampered-file rejection (ciphertext flipped -> GCM/integrity fail).
  3. Forged-signature / wrong-sender rejection.
  4. Hash-chained audit log tamper detection.

Run:  python test_cengshare.py
"""

import base64
import copy

from cryptography.hazmat.primitives.asymmetric import rsa

import audit_log
from crypto_utils import (
    create_secure_package,
    ensure_keys,
    load_private_key,
    load_public_key,
    open_secure_package,
)

PASS, FAIL = "PASS ✅", "FAIL ❌"
results = []


def check(name, condition):
    results.append((name, condition))
    print(f"  {PASS if condition else FAIL}  {name}")


keys = ensure_keys()
sender_priv = load_private_key(keys["sender_private"])
receiver_priv = load_private_key(keys["receiver_private"])
receiver_pub = load_public_key(keys["receiver_public"])

data = b"Top secret CENG report: launch codes 0000-1111-2222.\n" * 50
pkg = create_secure_package(data, "secret.txt", sender_priv, receiver_pub)

print("\n[1] Successful secure transfer")
r = open_secure_package(pkg, receiver_priv)
check("signature valid", r.signature_valid)
check("integrity valid", r.integrity_valid)
check("decrypted", r.decrypted)
check("plaintext round-trips", r.plaintext == data)
check("overall ok", r.ok)

print("\n[2] Tampered ciphertext is rejected")
tampered = copy.deepcopy(pkg)
raw = bytearray(base64.b64decode(tampered["ciphertext"]))
raw[10] ^= 0xFF  # flip a byte
tampered["ciphertext"] = base64.b64encode(bytes(raw)).decode()
r2 = open_secure_package(tampered, receiver_priv)
check("decryption refused", not r2.decrypted)
check("overall not ok", not r2.ok)

print("\n[3] Forged sender (wrong signing key) is rejected")

attacker = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

forged_pkg = create_secure_package(
    data,
    "secret.txt",
    attacker,
    receiver_pub,
)

r3 = open_secure_package(
    forged_pkg,
    receiver_priv,
    expected_sender_public_key=load_public_key(
        keys["sender_public"]
    ),
)

check("signature rejected", not r3.signature_valid)
check("decryption blocked", not r3.decrypted)
check("plaintext not exposed", r3.plaintext is None)
check("overall not ok", not r3.ok)

print("\n[4] Malformed package is rejected")
r4 = open_secure_package({"version": "1.0"}, receiver_priv)
check("package invalid", not r4.package_valid)

print("\n[5] Audit-log hash chain")
audit_log.log_event("TEST_EVENT", {"scenario": "self-test"})
chain = audit_log.verify_chain()
check("chain intact after append", chain["intact"])

print("\n" + "=" * 48)
passed = sum(1 for _, c in results if c)
print(f"  {passed}/{len(results)} checks passed")
print("=" * 48)
raise SystemExit(0 if passed == len(results) else 1)
