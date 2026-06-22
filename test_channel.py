"""
test_channel.py — Two-party (identity + channel) self-test for CENGShare.

Simulates Alice sending to Bob through the shared channel, then exercises the
trust checks that make this genuinely two-party:
  1. Bob receives and decrypts a package addressed to him.
  2. A tampered package on the channel is rejected.
  3. An impersonator (Mallory signing but claiming to be Alice) is rejected
     because Bob verifies against Alice's TRUSTED keyring key, not the
     embedded one.

Run:  python test_channel.py
"""

import base64
import copy
import json

import channel
import identity
from crypto_utils import (
    create_secure_package,
    open_secure_package,
    package_from_bytes,
    package_to_bytes,
)

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, condition):
    results.append((name, condition))
    print(f"  {PASS if condition else FAIL}  {name}")


# --- set up two identities -------------------------------------------------
for who in ("Alice", "Bob", "Mallory"):
    identity.create_identity(who)

data = b"Quarterly results - confidential. " * 40

print("\n[1] Alice -> Bob through the channel")
pkg = create_secure_package(
    data, "results.pdf",
    identity.get_private_key("Alice"),
    identity.get_public_key("Bob"),
    sender_name="Alice", recipient_name="Bob",
)
msg_id = channel.publish(package_to_bytes(pkg), "Alice", "Bob")
inbox = channel.inbox("Bob")
check("message is in Bob's inbox", any(m["msg_id"] == msg_id for m in inbox))
check("message NOT in Alice's inbox", not channel.inbox("Alice"))

received = package_from_bytes(channel.read_package(msg_id))
r = open_secure_package(
    received, identity.get_private_key("Bob"),
    expected_sender_public_key=identity.get_public_key("Alice"),
)
check("Bob verifies Alice's signature", r.signature_valid)
check("integrity holds", r.integrity_valid)
check("Bob decrypts the file", r.decrypted and r.plaintext == data)
check("overall ok", r.ok)

print("\n[2] Tampered package on the channel is rejected")
tampered = copy.deepcopy(received)
raw = bytearray(base64.b64decode(tampered["ciphertext"]))
raw[5] ^= 0xFF
tampered["ciphertext"] = base64.b64encode(bytes(raw)).decode()
rt = open_secure_package(
    tampered, identity.get_private_key("Bob"),
    expected_sender_public_key=identity.get_public_key("Alice"),
)
check("tampered package not ok", not rt.ok)

print("\n[3] Impersonation rejected (Mallory claims to be Alice)")
forged = create_secure_package(
    data, "results.pdf",
    identity.get_private_key("Mallory"),       # signed by Mallory
    identity.get_public_key("Bob"),
    sender_name="Alice", recipient_name="Bob",  # but claims to be Alice
)
# Bob trusts Alice's REAL key from the keyring:
rf = open_secure_package(
    forged, identity.get_private_key("Bob"),
    expected_sender_public_key=identity.get_public_key("Alice"),
)
check("impersonator's signature rejected", not rf.signature_valid)
check("impersonation overall not ok", not rf.ok)

print("\n[4] Verification without a trusted sender key is blocked")

unknown_result = open_secure_package(
    pkg,
    identity.get_private_key("Bob"),
    expected_sender_public_key=None,
)

check(
    "signature not trusted without keyring key",
    not unknown_result.signature_valid,
)

check(
    "decryption blocked without trusted sender key",
    not unknown_result.decrypted,
)

check(
    "plaintext not exposed without trusted sender key",
    unknown_result.plaintext is None,
)

check(
    "package not accepted without trusted sender key",
    not unknown_result.ok,
)

print("\n" + "=" * 48)
passed = sum(1 for _, c in results if c)
print(f"  {passed}/{len(results)} checks passed")
print("=" * 48)
raise SystemExit(0 if passed == len(results) else 1)
