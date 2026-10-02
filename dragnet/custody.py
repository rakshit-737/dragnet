"""Chain-of-custody: content hashing + tamper-evident hash-chained log."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def canonical_hash(obj) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


class CustodyLog:
    """Append-only, hash-chained log of evidence items; ``verify()`` detects any change."""

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def record(self, action: str, item_id: str, item_hash: str, actor: str = "dragnet",
               ts: str | None = None) -> dict:
        prev = self.entries[-1]["entry_hash"] if self.entries else self.GENESIS
        body = {
            "seq": len(self.entries),
            "ts": ts or datetime.now(timezone.utc).isoformat(),
            "action": action,
            "item_id": item_id,
            "item_hash": item_hash,
            "actor": actor,
            "prev_hash": prev,
        }
        body["entry_hash"] = canonical_hash(body)
        self.entries.append(body)
        return body

    def verify(self) -> bool:
        prev = self.GENESIS
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k != "entry_hash"}
            if e["seq"] != i or e["prev_hash"] != prev or canonical_hash(body) != e["entry_hash"]:
                return False
            prev = e["entry_hash"]
        return True


# ---------------------------------------------------------------- Ed25519 signing
# Optional: needs the ``cryptography`` package (the ``sign`` extra). The signature
# covers the head of the hash chain, so it commits to every entry before it.

def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise RuntimeError("signing needs the optional 'cryptography' package: pip install \"dragnet-attribution[sign]\" or, in a checkout, pip install -e \".[sign]\"") from e
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private PEM, public PEM)."""
    ser, Priv, _ = _crypto()
    k = Priv.generate()
    priv = k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    pub = k.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def sign_entries(entries: list[dict], private_pem: bytes) -> dict:
    """Sign the head hash of a custody chain with an Ed25519 PEM key (needs the ``sign`` extra).

    :returns: a dict with the algorithm, public key, head hash and signature.
    """
    ser, _, _ = _crypto()
    key = ser.load_pem_private_key(private_pem, password=None)
    head = entries[-1]["entry_hash"] if entries else CustodyLog.GENESIS
    msg = f"dragnet-custody-v1:{len(entries)}:{head}".encode()
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return {"alg": "Ed25519", "entries": len(entries), "head": head,
            "public_key": pub.hex(), "signature": key.sign(msg).hex()}


def verify_signed(entries: list[dict], sig: dict, public_pem: bytes | None = None) -> bool:
    """True iff the chain is intact and the signature over its head is valid.

    Pass ``public_pem`` to pin the expected signer; otherwise the embedded key is used
    (which only proves integrity, not identity)."""
    from cryptography.exceptions import InvalidSignature
    ser, _, Pub = _crypto()
    log = CustodyLog()
    log.entries = list(entries)
    if not log.verify() or sig.get("entries") != len(entries):
        return False
    head = entries[-1]["entry_hash"] if entries else CustodyLog.GENESIS
    if sig.get("head") != head:
        return False
    key = (ser.load_pem_public_key(public_pem) if public_pem
           else Pub.from_public_bytes(bytes.fromhex(sig["public_key"])))
    try:
        key.verify(bytes.fromhex(sig["signature"]), f"dragnet-custody-v1:{len(entries)}:{head}".encode())
    except InvalidSignature:
        return False
    return True
