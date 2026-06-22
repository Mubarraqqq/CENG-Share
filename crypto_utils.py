"""
crypto_utils.py — Cryptographic core for CENGShare.

Security model (per file transfer):
  Confidentiality : file body encrypted with AES-256-GCM (random key + nonce).
  Key protection  : the AES key is encrypted with the receiver's RSA public key
                    (RSA-OAEP). Only the receiver's private key can recover it.
  Integrity       : SHA-256 hash of the plaintext is stored in the package.
  Authentication  : the hash is digitally signed with the sender's RSA private
                    key (RSA-PSS). The receiver verifies it with the sender's
                    public key, proving origin and that nothing was altered.

Everything binary in a package is base64-encoded so the package is plain JSON.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYS_DIR = Path(__file__).parent / "keys"
PACKAGE_VERSION = "1.0"


# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #
def _generate_keypair(private_path: Path, public_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def ensure_keys() -> dict[str, Path]:
    """Create sender + receiver RSA keypairs on first run; return their paths.

    The sender keypair is used for signing/verifying.
    The receiver keypair is used for protecting/recovering the AES key.
    """
    KEYS_DIR.mkdir(exist_ok=True)
    paths = {
        "sender_private": KEYS_DIR / "sender_private.pem",
        "sender_public": KEYS_DIR / "sender_public.pem",
        "receiver_private": KEYS_DIR / "receiver_private.pem",
        "receiver_public": KEYS_DIR / "receiver_public.pem",
    }
    if not paths["sender_private"].exists():
        _generate_keypair(paths["sender_private"], paths["sender_public"])
    if not paths["receiver_private"].exists():
        _generate_keypair(paths["receiver_private"], paths["receiver_public"])
    return paths


def load_private_key(path: Path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_public_key(path_or_pem):
    data = path_or_pem
    if isinstance(path_or_pem, (str, Path)) and Path(path_or_pem).exists():
        data = Path(path_or_pem).read_bytes()
    if isinstance(data, str):
        data = data.encode()
    return serialization.load_pem_public_key(data)


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Encryption (sender side)
# --------------------------------------------------------------------------- #
def create_secure_package(
    plaintext: bytes,
    filename: str,
    sender_private_key,
    receiver_public_key,
    sender_name: str = "CENG",
    recipient_name: str | None = None,
) -> dict:
    """Encrypt, hash and sign a file, returning a JSON-serialisable package.

    sender_name / recipient_name are identity labels used by the channel for
    routing and by the receiver for trusted-key lookup. Metadata is NOT signed
    (only file_hash is), so the receiver must verify the sender via a trusted
    keyring copy of their public key, never the PEM embedded in the package.
    """
    # 1. Confidentiality: AES-256-GCM with a fresh random key + nonce.
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    # 2. Key protection: wrap the AES key with the receiver's RSA public key.
    encrypted_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Integrity: hash the plaintext.
    file_hash = sha256_hex(plaintext)

    # 4. Authentication: sign the hash with the sender's RSA private key.
    signature = sender_private_key.sign(
        file_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    sender_public_pem = (
        sender_private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )

    return {
        "version": PACKAGE_VERSION,
        "metadata": {
            "filename": filename,
            "size": len(plaintext),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sender": sender_name,
            "recipient": recipient_name,
        },
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "file_hash": file_hash,
        "signature": base64.b64encode(signature).decode(),
        "sender_public_key": sender_public_pem,
    }


# --------------------------------------------------------------------------- #
# Decryption + verification (receiver side)
# --------------------------------------------------------------------------- #
class VerificationResult:
    """Structured outcome of opening a package, consumed by the UI + IDS."""

    def __init__(self):
        self.package_valid = False        # parsed and structurally complete
        self.signature_valid = False      # signed by the expected sender
        self.integrity_valid = False      # recomputed hash matches signed hash
        self.decrypted = False            # AES-GCM decryption succeeded
        self.plaintext: bytes | None = None
        self.filename: str | None = None
        self.errors: list[str] = []

    @property
    def ok(self) -> bool:
        return (
            self.package_valid
            and self.signature_valid
            and self.integrity_valid
            and self.decrypted
        )

    def as_dict(self) -> dict:
        return {
            "package_valid": self.package_valid,
            "signature_valid": self.signature_valid,
            "integrity_valid": self.integrity_valid,
            "decrypted": self.decrypted,
            "errors": self.errors,
        }


_REQUIRED_FIELDS = (
    "version", "metadata", "nonce", "ciphertext",
    "encrypted_key", "file_hash", "signature", "sender_public_key",
)


def open_secure_package(
    package: dict,
    receiver_private_key,
    expected_sender_public_key=None,
) -> VerificationResult:
    """Verify signature + integrity, then decrypt.

    Order matters: we authenticate the signed hash *before* trusting the
    contents, then confirm the decrypted bytes match that hash. Any failure
    leaves the corresponding flag False so the IDS can classify the event.
    """
    result = VerificationResult()

    # --- structural validation ---------------------------------------------
    if not isinstance(package, dict) or any(f not in package for f in _REQUIRED_FIELDS):
        result.errors.append("Malformed package: missing required fields.")
        return result
    result.package_valid = True
    result.filename = package.get("metadata", {}).get("filename", "recovered.bin")

    try:
        nonce = base64.b64decode(package["nonce"])
        ciphertext = base64.b64decode(package["ciphertext"])
        encrypted_key = base64.b64decode(package["encrypted_key"])
        signature = base64.b64decode(package["signature"])
        claimed_hash = package["file_hash"]
    except Exception as exc:  # noqa: BLE001 - any decode failure = invalid package
        result.package_valid = False
        result.errors.append(f"Malformed package: cannot decode fields ({exc}).")
        return result

    # --- authentication: verify the signature over the claimed hash ---------
    sender_pub = expected_sender_public_key or load_public_key(
        package["sender_public_key"]
    )
    try:
        sender_pub.verify(
            signature,
            claimed_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        result.signature_valid = True
    except InvalidSignature:
        result.errors.append("Invalid digital signature: sender unverified or hash altered.")

    # --- recover the AES key -------------------------------------------------
    try:
        aes_key = receiver_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:  # noqa: BLE001 - wrong key / corrupted wrapping
        result.errors.append("Failed to recover AES key (wrong receiver key or tampered package).")
        return result

    # --- decrypt -------------------------------------------------------------
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
        result.decrypted = True
    except InvalidTag:
        result.errors.append("Decryption failed: ciphertext or nonce tampered (GCM tag mismatch).")
        return result

    # --- integrity: recomputed hash must match the signed hash --------------
    actual_hash = sha256_hex(plaintext)
    if actual_hash == claimed_hash:
        result.integrity_valid = True
        result.plaintext = plaintext
    else:
        result.errors.append(
            f"Integrity check failed: hash mismatch "
            f"(expected {claimed_hash[:12]}…, got {actual_hash[:12]}…)."
        )

    return result


# --------------------------------------------------------------------------- #
# Package (de)serialisation helpers
# --------------------------------------------------------------------------- #
def package_to_bytes(package: dict) -> bytes:
    return json.dumps(package, indent=2).encode()


def package_from_bytes(raw: bytes) -> dict:
    return json.loads(raw.decode())
