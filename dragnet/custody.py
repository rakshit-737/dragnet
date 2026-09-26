"""Chain-of-custody: content hashing + tamper-evident hash-chained log."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def canonical_hash(obj) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


class CustodyLog:
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
