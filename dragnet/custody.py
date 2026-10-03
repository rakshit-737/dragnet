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
# Optional: needs the ``cryptography`` package (the ``sign`` extra). A v2 signature covers the
# whole report body (verdict, confidence, hypotheses, weights, ACH matrix, custody chain) via
# its canonical SHA-256 plus the head of the hash chain. v1 signatures (DRAGNET <= 1.1.0)
# covered only the custody chain head; :func:`verify_signed` reports them as legacy.

SIGNATURE_KEY = "custody_signature"
INSTALL_HINT = ('pip install "dragnet-attribution[sign] @ git+https://github.com/rakshit-737/dragnet-actor-attribution" '
                '(or pip install -e ".[sign]" in a checkout)')


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise ImportError(f"signing needs the optional 'cryptography' package: {INSTALL_HINT}",
                          name="cryptography") from e
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def report_body_hash(report: dict) -> str:
    """Canonical SHA-256 of a JSON report without its signature block."""
    return canonical_hash({k: v for k, v in report.items() if k != SIGNATURE_KEY})


def _message(n: int, head: str, body: str | None) -> bytes:
    if body is None:
        return f"dragnet-custody-v1:{n}:{head}".encode()
    return f"dragnet-report-v2:{n}:{head}:{body}".encode()


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private PEM, public PEM)."""
    ser, Priv, _ = _crypto()
    k = Priv.generate()
    priv = k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    pub = k.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def sign_entries(entries: list[dict], private_pem: bytes, report: dict | None = None) -> dict:
    """Sign a report with an Ed25519 PEM key (needs the ``sign`` extra).

    With ``report`` (the JSON report dict, without a signature block) the signature covers the
    report body and the custody chain head (v2); without it only the chain head (v1, legacy).

    :returns: a dict with the algorithm, version, public key, head hash, body hash and signature.
    """
    ser, _, _ = _crypto()
    key = ser.load_pem_private_key(private_pem, password=None)
    head = entries[-1]["entry_hash"] if entries else CustodyLog.GENESIS
    body = report_body_hash(report) if report is not None else None
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    out = {"alg": "Ed25519", "version": 2 if body else 1, "entries": len(entries), "head": head,
           "public_key": pub.hex(), "signature": key.sign(_message(len(entries), head, body)).hex()}
    if body:
        out |= {"body_sha256": body, "covers": "report body (verdict, scores, weights, matrix) + custody chain"}
    return out


def verify_signed(entries: list[dict], sig: dict, public_pem: bytes | None = None,
                  report: dict | None = None) -> bool:
    """True iff the chain is intact and the signature is valid.

    For a v2 signature pass the full ``report``: its body is re-hashed, so any edit to the
    verdict, confidence, hypotheses, weights or matrix fails verification. Pass ``public_pem``
    to pin the expected signer; otherwise the embedded key is used (integrity only, not
    identity)."""
    ser, _, Pub = _crypto()
    from cryptography.exceptions import InvalidSignature
    log = CustodyLog()
    log.entries = list(entries)
    if not log.verify() or sig.get("entries") != len(entries):
        return False
    head = entries[-1]["entry_hash"] if entries else CustodyLog.GENESIS
    if sig.get("head") != head:
        return False
    body = None
    if sig.get("version", 1) >= 2:
        if report is None or sig.get("body_sha256") != (body := report_body_hash(report)):
            return False
    key = (ser.load_pem_public_key(public_pem) if public_pem
           else Pub.from_public_bytes(bytes.fromhex(sig["public_key"])))
    try:
        key.verify(bytes.fromhex(sig["signature"]), _message(len(entries), head, body))
    except InvalidSignature:
        return False
    return True
