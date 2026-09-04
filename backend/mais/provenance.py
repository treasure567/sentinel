"""
provenance.py — an append-only, tamper-evident audit log.

Every Score, Verdict and Action is appended as one JSON line whose hash chains
to the previous entry (each record carries the previous record's hash), so any
later edit to the middle of the log is detectable. This is the prototype's
realisation of the report's immutable provenance requirement; a production
system would add real digital signatures over each entry_hash.
"""
from __future__ import annotations
import json
import hashlib
import os
from typing import Any, Dict


class Provenance:
    def __init__(self, path: str) -> None:
        self.path = path
        self._prev = "0" * 64
        # start each run with a fresh log
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write("")

    def record(self, kind: str, payload: Dict[str, Any]) -> str:
        entry = {"kind": kind, "prev_hash": self._prev, "payload": payload}
        body = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256((self._prev + body).encode()).hexdigest()
        entry["entry_hash"] = entry_hash
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self._prev = entry_hash
        return entry_hash

    @staticmethod
    def verify(path: str) -> bool:
        """Re-walk the chain and confirm no entry has been altered."""
        prev = "0" * 64
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                stored = rec.pop("entry_hash")
                if rec.get("prev_hash") != prev:
                    return False
                body = json.dumps(rec, sort_keys=True)
                if hashlib.sha256((prev + body).encode()).hexdigest() != stored:
                    return False
                prev = stored
        return True
