"""
api.py — the JSON + SSE API in front of the agent engine (standard library only).

Runs the simulation in a background thread and exposes it to the React SPA.

  GET  /stream                      live snapshot stream (Server-Sent Events)
  GET  /api/state                   one-shot snapshot
  GET  /api/meta                    playbooks, kinds, categories, agent roster
  GET  /api/agents                  all detection agents
  GET  /api/agent/<id>              one agent in detail
  GET  /api/incidents               case list
  GET  /api/incident/<id>           full case file
  GET  /api/entities[?category=]    the directory, with live risk
  GET  /api/entity/<uid>            one person's profile, events and cases
  GET  /api/entity/<uid>/pc         their workstation: processes, connections, disk
  GET  /api/audit                   hash-chained audit entries
  GET  /api/audit/verify            re-walk the chain
  GET  /api/replay?playbook=&poison= a recorded, scrubbable run
  POST /api/simulate                start a simulation
  POST /api/simulation/<id>/stop    stop one
  POST /api/simulations/stop        stop all
  POST /api/entity/<uid>/isolate    {"value": true|false}
  POST /api/entity/<uid>/pause      {"value": true|false}
  POST /api/shell/<uid>             {"cmd": "..."} -> command output
  POST /api/reset                   reset the simulation

CORS is open so the Vite dev server (a different port) can call it.
"""
from __future__ import annotations
import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

from mais.engine import Engine, AGENT_INFO, AGENT_SPECS
from mais.generator import PLAYBOOKS, KINDS
from mais import entities as E
from mais.provenance import Provenance
from db import DB

_TMP = tempfile.gettempdir()
DB_PATH = os.environ.get("SENTINEL_DB", os.path.join(_TMP, "sentinel.db"))
LOG_PATH = os.path.join(_TMP, "sentinel_provenance.jsonl")


class Sim:
    """Owns the live engine and steps it on a timer in a background thread."""

    def __init__(self, tick_seconds: float = 1.0):
        self.tick_seconds = tick_seconds
        self.db = DB(DB_PATH)
        self.db.reset()
        self.lock = threading.Lock()
        self.engine = Engine(seed=7, log_path=LOG_PATH, sink=self.db.sink)
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            with self.lock:
                self.engine.step()
            time.sleep(self.tick_seconds)

    def call(self, fn, *a, **kw):
        with self.lock:
            return fn(self.engine, *a, **kw)

    def reset(self):
        with self.lock:
            for e in E.all_entities():
                E.set_isolated(e.uid, False)
                E.set_paused(e.uid, False)
            self.db.reset()
            self.engine = Engine(seed=7, log_path=LOG_PATH, sink=self.db.sink)


REPLAYS: dict = {}


def record_replay(playbook: str, poison: str | None, ticks: int = 24) -> dict:
    """Run a playbook headless on a throwaway engine, capturing a frame per tick."""
    for e in E.all_entities():
        E.set_isolated(e.uid, False)
    eng = Engine(seed=7, log_path=os.path.join(_TMP, "sentinel_replay.jsonl"))
    uid = E.TARGET_UID
    frames, inject_at = [], 2
    for t in range(ticks):
        if t == inject_at:
            eng.start_simulation(uid, playbook, intensity="high", poison_agent=poison)
        eng.step()
        frames.append(eng.snapshot())
    inc = None
    for s in eng.incidents.list():
        if s["entity"] == uid:
            inc = eng.incidents.get(s["id"]); break
    for e in E.all_entities():
        E.set_isolated(e.uid, False)
    return {"playbook": playbook, "poison": poison, "frames": frames,
            "incident": inc, "inject_at": inject_at,
            "label": PLAYBOOKS.get(playbook, {}).get("label", playbook)}


def make_handler(sim: Sim):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        # ---------- helpers ----------
        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self._cors(); self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return {}

        def do_OPTIONS(self):
            self.send_response(204); self._cors(); self.end_headers()

        # ---------- GET ----------
        def do_GET(self):
            p = urlparse(self.path)
            path, q = p.path, parse_qs(p.query)

            if path == "/stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self._cors(); self.end_headers()
                try:
                    while True:
                        frame = "data: " + json.dumps(sim.call(lambda e: e.snapshot())) + "\n\n"
                        self.wfile.write(frame.encode()); self.wfile.flush()
                        time.sleep(sim.tick_seconds)
                except (BrokenPipeError, ConnectionResetError):
                    return

            elif path == "/api/state":
                self._json(sim.call(lambda e: e.snapshot()))

            elif path == "/api/meta":
                self._json({
                    "org": E.ORG, "department": E.DEPT,
                    "playbooks": [{"id": k, **v} for k, v in PLAYBOOKS.items()],
                    "kinds": KINDS,
                    "categories": E.categories(),
                    "intensities": ["low", "medium", "high"],
                    "agents": [{"id": a, "domain": d, "title": AGENT_INFO[a]["title"],
                                "short": AGENT_INFO[a]["short"]} for a, d in AGENT_SPECS],
                    "population": len(E.all_entities()),
                })

            elif path == "/api/agents":
                self._json(sim.call(lambda e: e.agents_snapshot()))

            elif path.startswith("/api/agent/"):
                aid = path.rsplit("/", 1)[-1]
                found = next((a for a in sim.call(lambda e: e.agents_snapshot())
                              if a["id"] == aid), None)
                self._json(found or {"error": "not found"}, 200 if found else 404)

            elif path == "/api/simulations":
                self._json({"simulations": sim.call(lambda e: e.gen.simulations())})

            elif path == "/api/incidents":
                self._json({"incidents": sim.call(lambda e: e.incidents.list()),
                            "db": sim.db.counts()})

            elif path.startswith("/api/incident/"):
                iid = path.rsplit("/", 1)[-1]
                d = sim.call(lambda e: e.incidents.get(iid))
                self._json(d or {"error": "not found"}, 200 if d else 404)

            elif path == "/api/entities":
                ents = sim.call(lambda e: e.entities_snapshot())
                cat = (q.get("category") or [None])[0]
                if cat and cat != "All":
                    ents = [x for x in ents if x["category"] == cat]
                self._json({"entities": ents, "categories": E.categories()})

            elif path.endswith("/pc") and path.startswith("/api/entity/"):
                uid = unquote(path[len("/api/entity/"):-len("/pc")])
                m = sim.call(lambda e: e.machine(uid))
                self._json(m.summary() if m else {"error": "not found"}, 200 if m else 404)

            elif path.startswith("/api/entity/"):
                uid = unquote(path[len("/api/entity/"):])
                snap = sim.call(lambda e: {x["uid"]: x for x in e.entities_snapshot()}.get(uid))
                if not snap:
                    self._json({"error": "not found"}, 404); return
                snap["events"] = sim.db.events_for(uid, 80)
                self._json(snap)

            elif path == "/api/audit":
                self._json({"audit": sim.db.recent_audit(80), "db": sim.db.counts()})

            elif path == "/api/audit/verify":
                self._json({"intact": Provenance.verify(LOG_PATH), "log": LOG_PATH})

            elif path == "/api/replay":
                pb = (q.get("playbook") or ["exfiltration"])[0]
                po = (q.get("poison") or [""])[0] or None
                key = f"{pb}:{po}"
                if key not in REPLAYS:
                    REPLAYS[key] = record_replay(pb, po)
                self._json(REPLAYS[key])

            elif path == "/api/health":
                self._json({"ok": True})
            else:
                self._json({"error": "not found"}, 404)

        # ---------- POST ----------
        def do_POST(self):
            path = urlparse(self.path).path
            body = self._body()

            if path == "/api/simulate":
                uid = body.get("uid") or E.TARGET_UID
                if uid not in E.DIRECTORY:
                    self._json({"error": "unknown entity"}, 400); return
                out = sim.call(lambda e: e.start_simulation(
                    uid, body.get("playbook", "exfiltration"),
                    body.get("kinds") or None, body.get("intensity", "medium"),
                    body.get("poison_agent") or None))
                self._json({"ok": True, "simulation": out})

            elif path.startswith("/api/simulation/") and path.endswith("/stop"):
                sid = int(path.split("/")[3])
                ok = sim.call(lambda e: e.stop_simulation(sid))
                self._json({"ok": ok})

            elif path == "/api/simulations/stop":
                sim.call(lambda e: e.stop_all_simulations())
                self._json({"ok": True})

            elif path.startswith("/api/entity/") and path.endswith("/isolate"):
                uid = unquote(path[len("/api/entity/"):-len("/isolate")])
                val = bool(body.get("value", True))
                ok = sim.call(lambda e: e.set_isolated(uid, val))
                self._json({"ok": ok, "isolated": val})

            elif path.startswith("/api/entity/") and path.endswith("/pause"):
                uid = unquote(path[len("/api/entity/"):-len("/pause")])
                val = bool(body.get("value", True))
                ok = sim.call(lambda e: e.set_paused(uid, val))
                self._json({"ok": ok, "paused": val})

            elif path.startswith("/api/shell/"):
                uid = unquote(path[len("/api/shell/"):])
                cmd = (body.get("cmd") or "").strip()
                m = sim.call(lambda e: e.machine(uid))
                if not m:
                    self._json({"error": "unknown machine"}, 404); return
                out = m.run(cmd)
                self._json({"output": out, "prompt": m.prompt(), "cwd": m.cwd})

            elif path == "/api/reset":
                sim.reset(); REPLAYS.clear(); self._json({"ok": True})
            else:
                self._json({"error": "not found"}, 404)
    return H


def serve(host="127.0.0.1", port=8000, tick_seconds=1.0):
    sim = Sim(tick_seconds=tick_seconds)
    httpd = ThreadingHTTPServer((host, port), make_handler(sim))
    print("\n  Sentinel API — Multi-Agent Insider-Threat Detection")
    print("  " + "-" * 54)
    print(f"  Monitoring {len(E.all_entities())} people · {E.DEPT}")
    print(f"  API + live stream:  http://{host}:{port}")
    print(f"  Database:           {DB_PATH}")
    print("  Ctrl+C to stop.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped."); httpd.shutdown()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="seconds per simulation tick (higher = slower flow)")
    a = ap.parse_args()
    serve(a.host, a.port, a.speed)
