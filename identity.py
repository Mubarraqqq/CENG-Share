

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from channel import KEYRING_DIR

BASE = Path(__file__).parent
IDENTITIES_DIR = BASE / "identities"


def _identity_dir(name: str) -> Path:
    return IDENTITIES_DIR / name


def identity_exists(name: str) -> bool:
    return (_identity_dir(name) / "private.pem").exists()


def create_identity(name: str) -> None:
    """Generate a keypair for `name` and publish its public key to the keyring."""
    name = name.strip()
    if not name:
        raise ValueError("Identity name cannot be empty.")
    if identity_exists(name):
        return  # idempotent

    d = _identity_dir(name)
    d.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (d / "private.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (d / "public.pem").write_bytes(public_pem)
    publish_public_key(name, public_pem)


def publish_public_key(name: str, public_pem: bytes | None = None) -> None:
    """Copy an identity's public key into the shared keyring (the 'channel')."""
    KEYRING_DIR.mkdir(parents=True, exist_ok=True)
    if public_pem is None:
        public_pem = (_identity_dir(name) / "public.pem").read_bytes()
    (KEYRING_DIR / f"{name}.pem").write_bytes(public_pem)


def list_identities() -> list[str]:
    """Identities whose PRIVATE key is held locally (users you can act as)."""
    if not IDENTITIES_DIR.exists():
        return []
    return sorted(
        d.name for d in IDENTITIES_DIR.iterdir()
        if (d / "private.pem").exists()
    )


def list_contacts() -> list[str]:
    """Identities whose PUBLIC key is in the keyring (users you can reach)."""
    if not KEYRING_DIR.exists():
        return []
    return sorted(p.stem for p in KEYRING_DIR.glob("*.pem"))


def get_private_key(name: str):
    data = (_identity_dir(name) / "private.pem").read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def get_public_key(name: str):
    """Load a contact's TRUSTED public key from the keyring (None if unknown)."""
    path = KEYRING_DIR / f"{name}.pem"
    if not path.exists():
        return None
    return serialization.load_pem_public_key(path.read_bytes())


def public_pem(name: str) -> str | None:
    path = KEYRING_DIR / f"{name}.pem"
    return path.read_text() if path.exists() else None


def fingerprint(name: str) -> str | None:
    """Short SHA-256 fingerprint of a keyring public key, for visual ID."""
    pub = get_public_key(name)
    if pub is None:
        return None
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    hexd = digest.finalize().hex()
    return ":".join(hexd[i:i + 4] for i in range(0, 16, 4)).upper()
