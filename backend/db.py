"""
db.py — SQLite persistence for the prototype.

Every telemetry event, and every audit entry (score / verdict / action with its
hash-chain link), is written to a local SQLite file as the simulation runs, so
the data is durable and queryable independently of the live process. The API
reads recent rows from here for the Audit and Events views; the richer incident
objects are held in memory by the engine and also serialisable here.

SQLite ships with Python (the `sqlite3` module), so this adds no dependency.
Writes come from the engine's sink callback on a single background thread.
"""
from __future__ import annotations
import sqlite3
import json
import threading
import time
from typing import Any, Dict, List

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, tick INTEGER, domain TEXT, entity TEXT, kind TEXT, features TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, tick INTEGER, kind TEXT, hash TEXT, payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity);
CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit(kind);
"""


class DB:
    def __init__(self, path: str = "sentinel.db"):
        self.path = path
        self._lock = threading.Lock()
        self.ok = False
        self.conn = None
        # Try the requested path; if the filesystem can't host a SQLite file
        # (e.g. a network/virtual mount without proper locking), fall back to a
        # temp-dir copy, and finally to an in-memory DB, so the app never fails
        # to start over persistence.
        import tempfile, os
        candidates = [path,
                      os.path.join(tempfile.gettempdir(), "sentinel_" + str(os.getpid()) + ".db"),
                      ":memory:"]
        for cand in candidates:
            try:
                conn = sqlite3.connect(cand, check_same_thread=False)
                conn.executescript(SCHEMA)
                conn.commit()
                self.conn = conn
                self.path = cand
                self.ok = True
                if cand != path:
                    print(f"  [db] '{path}' not writable here; using {cand}")
                break
            except Exception as e:
                last = e
                continue
        if not self.ok:
            print("  [db] persistence disabled:", last)

    def reset(self) -> None:
        if not self.ok:
            return
        with self._lock:
            self.conn.execute("DELETE FROM events")
            self.conn.execute("DELETE FROM audit")
            self.conn.commit()

    def sink(self, kind: str, row: Dict[str, Any]) -> None:
        """Engine sink callback: 'event' or 'audit'."""
        if not self.ok:
            return
        with self._lock:
            if kind == "event":
                self.conn.execute(
                    "INSERT INTO events(ts,tick,domain,entity,kind,features) VALUES(?,?,?,?,?,?)",
                    (row.get("ts", time.time()), row.get("tick"), row.get("domain"),
                     row.get("entity"), row.get("kind"), json.dumps(row.get("features", {}))))
            elif kind == "audit":
                self.conn.execute(
                    "INSERT INTO audit(ts,tick,kind,hash,payload) VALUES(?,?,?,?,?)",
                    (row.get("ts", time.time()), row.get("tick"), row.get("kind"),
                     row.get("hash"), json.dumps(row.get("payload", {}))))
            # commit lazily-ish: every write commits (small volume in the demo)
            self.conn.commit()

    # ---- reads ----
    def recent_audit(self, limit: int = 60, kind: str | None = None) -> List[Dict[str, Any]]:
        if not self.ok:
            return []
        with self._lock:
            if kind:
                cur = self.conn.execute(
                    "SELECT ts,tick,kind,hash,payload FROM audit WHERE kind=? ORDER BY id DESC LIMIT ?",
                    (kind, limit))
            else:
                cur = self.conn.execute(
                    "SELECT ts,tick,kind,hash,payload FROM audit ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
        return [{"ts": r[0], "tick": r[1], "kind": r[2], "hash": r[3],
                 "payload": json.loads(r[4])} for r in rows]

    def events_for(self, entity: str, limit: int = 80) -> List[Dict[str, Any]]:
        if not self.ok:
            return []
        with self._lock:
            cur = self.conn.execute(
                "SELECT ts,tick,domain,kind,features FROM events WHERE entity=? ORDER BY id DESC LIMIT ?",
                (entity, limit))
            rows = cur.fetchall()
        return [{"ts": r[0], "tick": r[1], "domain": r[2], "kind": r[3],
                 "features": json.loads(r[4])} for r in rows]

    def counts(self) -> Dict[str, int]:
        if not self.ok:
            return {"events": 0, "audit": 0}
        with self._lock:
            e = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            a = self.conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        return {"events": e, "audit": a}
