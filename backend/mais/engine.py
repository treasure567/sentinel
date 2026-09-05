"""
engine.py — the simulation engine.

Each tick runs one perceive-reason-act cycle of the whole system: the generator
emits telemetry for the department, the detection agents score it, the fusion
agent combines their evidence (and watches for a subverted agent), the response
agent acts within its disruption budget, and everything is recorded as incidents,
provenance and (optionally) rows in SQLite.

The engine also owns the analyst's controls: starting and stopping simulations,
isolating a host, pausing an entity's traffic, and the per-entity virtual
machines an analyst can open a shell onto.
"""
from __future__ import annotations
import time
from collections import deque, defaultdict
from typing import Dict, List, Any, Optional, Callable

from .bus import Bus
from .contracts import (Event, Score, Verdict, Action,
                        TOPIC_EVENT, TOPIC_SCORE, TOPIC_VERDICT, TOPIC_ACTION)
from .generator import Generator, PLAYBOOKS, KINDS
from .agents.detection import DetectionAgent
from .fusion import FusionAgent
from .response import ResponseAgent
from .provenance import Provenance
from .incidents import IncidentStore
from .shell import Machine
from . import entities as E

AGENT_SPECS = [
    ("net-flow", "network"),
    ("host-proc", "host"),
    ("id-logon", "identity"),
    ("file-dev", "file"),
]

AGENT_INFO = {
    "net-flow": dict(
        title="Network Flow Agent", domain="network", short="Network",
        detector="Per-entity statistical flow model (volume + destination novelty)",
        watches="outbound volume, destination novelty, connection bursts",
        features=["bytes_out", "dst_novelty"],
        placement="Mirror port on the departmental core switch",
        mitre=["T1041 Exfiltration over C2", "T1071 Application Layer Protocol"]),
    "host-proc": dict(
        title="Host Process Agent", domain="host", short="Host",
        detector="Per-user process-rarity and reach model",
        watches="rare process launches, persistence, hosts reached",
        features=["proc_rare", "hosts_touched"],
        placement="Endpoint sensor on each managed workstation",
        mitre=["T1059 Command & Scripting", "T1543 Create or Modify System Process"]),
    "id-logon": dict(
        title="Identity / Logon Agent", domain="identity", short="Identity",
        detector="Behavioural logon model (hour, location novelty, failures)",
        watches="odd-hour logons, unfamiliar locations, failed-auth bursts",
        features=["logon_hour", "geo_novelty", "fail_count"],
        placement="Directory and SSO authentication logs",
        mitre=["T1110 Brute Force", "T1078 Valid Accounts"]),
    "file-dev": dict(
        title="File / Device Agent", domain="file", short="File",
        detector="Sensitivity-weighted file and removable-media model",
        watches="sensitive-file access, large writes to removable media",
        features=["file_sensitivity", "usb_bytes"],
        placement="File server auditing and endpoint device control",
        mitre=["T1213 Data from Information Repositories",
               "T1052 Exfiltration over Physical Medium"]),
}


class EnterpriseState:
    def __init__(self) -> None:
        self.contained: Dict[str, str] = {}

    def apply(self, a: Action) -> None:
        if a.approved and a.kind in ("quarantine", "suspend", "restrict"):
            self.contained[a.entity] = a.kind
            if a.kind in ("quarantine", "suspend"):
                E.set_isolated(a.entity, True)


class Engine:
    def __init__(self, seed: int = 7, log_path: str = "provenance_log.jsonl",
                 conflict_threshold: float = 0.28, budget: float = 0.15,
                 sink: Optional[Callable[[str, dict], None]] = None):
        self.bus = Bus()
        self.gen = Generator(seed=seed)
        self.enterprise = EnterpriseState()
        self.prov = Provenance(log_path)
        self.incidents = IncidentStore()
        self.sink = sink
        self.machines: Dict[str, Machine] = {}

        self.detectors: List[DetectionAgent] = [
            DetectionAgent(aid, dom, poison_check=lambda: self.gen.poisoned_agents)
            for aid, dom in AGENT_SPECS
        ]
        self.fusion = FusionAgent(conflict_threshold=conflict_threshold)
        self.response = ResponseAgent(budget=budget)

        for d in self.detectors:
            self.bus.subscribe(TOPIC_EVENT, d.perceive)
        self.bus.subscribe(TOPIC_SCORE, self.fusion.perceive)
        self.bus.subscribe(TOPIC_VERDICT, self.response.perceive)
        self.bus.subscribe(TOPIC_SCORE, lambda s: self._audit("score", s.to_json()))
        self.bus.subscribe(TOPIC_VERDICT, lambda v: self._audit("verdict", v.to_json()))
        self.bus.subscribe(TOPIC_ACTION, lambda a: self._audit("action", a.to_json()))

        self.tick = 0
        self.events_seen = 0
        self.last_scores: Dict[str, Score] = {}
        self.spark: Dict[str, deque] = {a: deque(maxlen=48) for a, _ in AGENT_SPECS}
        self.verdicts: Dict[str, Verdict] = {}
        self.timeline: deque = deque(maxlen=80)
        self.log: deque = deque(maxlen=120)
        self.flow_pulses: List[Dict[str, Any]] = []
        self.stats = defaultdict(int)
        self.entity_risk: Dict[str, Dict[str, Any]] = {}
        # agent heartbeats: each agent beats once per cycle it processed work
        self.beats: Dict[str, dict] = {
            aid: {"n": 0, "last": time.time(), "interval_ms": 700, "events": 0, "latency_ms": 0.0}
            for aid, _ in AGENT_SPECS}
        self.warm(cycles=45)

    # ------------------------------------------------------------- plumbing
    def _audit(self, kind: str, payload: dict) -> None:
        h = self.prov.record(kind, payload)
        if self.sink:
            self.sink("audit", {"kind": kind, "hash": h, "payload": payload,
                                "ts": time.time(), "tick": self.tick})

    def warm(self, cycles: int = 45) -> None:
        """Train every detector on every person's normal behaviour before going live."""
        for _ in range(cycles):
            for ev in self.gen.warm_tick():
                for d in self.detectors:
                    d.warm(ev)
        self.gen.t = 0

    def machine(self, uid: str) -> Optional[Machine]:
        if uid not in E.DIRECTORY:
            return None
        if uid not in self.machines:
            self.machines[uid] = Machine(uid)
        m = self.machines[uid]
        m.set_attack(self.gen.active_kinds_for(uid))
        return m

    # ------------------------------------------------------ analyst controls
    def start_simulation(self, uid: str, playbook="exfiltration", kinds=None,
                         intensity="medium", poison_agent=None) -> dict:
        sim = self.gen.start_simulation(uid, playbook, kinds, intensity, poison_agent)
        e = E.get(uid)
        self.machine(uid)                      # grow the forensic artefacts
        extra = f" with {poison_agent} subverted" if poison_agent else ""
        self._logline(f"Simulation started — {sim.label} on {e.name} ({e.host} · {e.ip}){extra}.")
        self.stats.clear()
        return sim.to_json()

    def stop_simulation(self, sim_id: int) -> bool:
        ok = self.gen.stop_simulation(sim_id)
        if ok:
            self._logline(f"Simulation {sim_id} stopped.")
        return ok

    def stop_all_simulations(self) -> None:
        self.gen.stop_all()
        for m in self.machines.values():
            m.clear_attack()
        self._logline("All simulations stopped.")

    def set_isolated(self, uid: str, value: bool) -> bool:
        ok = E.set_isolated(uid, value)
        if ok:
            e = E.get(uid)
            if value:
                self.enterprise.contained[uid] = "isolated"
            else:
                self.enterprise.contained.pop(uid, None)
            self._logline(f"{e.host} ({e.name}) {'isolated from the network' if value else 'returned to the network'} by the analyst.")
        return ok

    def set_paused(self, uid: str, value: bool) -> bool:
        ok = E.set_paused(uid, value)
        if ok:
            e = E.get(uid)
            self._logline(f"Telemetry for {e.name} ({e.host}) {'paused' if value else 'resumed'}.")
        return ok

    # ------------------------------------------------------------ main cycle
    def step(self) -> None:
        self.tick += 1
        self.flow_pulses = []
        t0 = time.perf_counter()

        events = self.gen.tick()
        self.events_seen += len(events)
        ev_by_entity: Dict[str, List[Event]] = defaultdict(list)
        for ev in events:
            self.bus.publish(TOPIC_EVENT, ev)
            ev_by_entity[ev.entity].append(ev)
            if self.sink:
                self.sink("event", {**ev.to_json(), "tick": self.tick})

        seen_by_agent = defaultdict(int)
        for ev in events:
            for aid, dom in AGENT_SPECS:
                if ev.domain == dom:
                    seen_by_agent[aid] += 1

        for d in self.detectors:
            d.reason()
            produced = d.act()
            beat = self.beats[d.agent_id]
            beat["events"] += seen_by_agent.get(d.agent_id, 0)
            if produced:
                beat["n"] += 1
                now = time.time()
                beat["interval_ms"] = int(max(120, min(2500, (now - beat["last"]) * 1000)))
                beat["last"] = now
                # the score the dashboard shows for this agent is its highest this
                # tick — the subject it is most concerned about
                headline = max(produced, key=lambda x: x.score)
                self.last_scores[d.agent_id] = headline
                self.spark[d.agent_id].append(round(headline.score, 3))
                self.flow_pulses.append({"edge": f"{d.domain}->fusion",
                                         "hot": headline.score >= 0.5})
            else:
                self.spark[d.agent_id].append(0.0)
            for s in produced:
                self.bus.publish(TOPIC_SCORE, s)
                for ev in ev_by_entity.get(s.entity, []):
                    if ev.domain == s.domain:
                        self.incidents.record_event(s.entity, self.tick, ev.domain,
                                                    ev.kind, ev.features, s.score)

        scn_label = self._scenario_label()
        self.fusion.reason()
        for v in self.fusion.act():
            self.verdicts[v.entity] = v
            self.bus.publish(TOPIC_VERDICT, v)
            self.incidents.update_from_verdict(v, self.tick, scn_label)
            self.entity_risk[v.entity] = {"risk": round(v.risk, 3), "tier": v.tier,
                                          "conflict": round(v.conflict, 3), "alarm": v.alarm}
            self.flow_pulses.append({"edge": "fusion->response",
                                     "hot": v.tier in ("High", "Critical")})
            if v.alarm:
                self.stats["alarms"] += 1
                nm = E.get(v.entity).name if E.get(v.entity) else v.entity
                self._logline(f"CONFLICT ALARM on {nm}: K={v.conflict:.2f} — an agent is contradicting the others.")

        self.response.reason()
        a = self.response.act()
        if a is not None:
            self.bus.publish(TOPIC_ACTION, a)
            self.enterprise.apply(a)
            self.incidents.record_action(a, self.tick)
            self.flow_pulses.append({"edge": "response->explain", "hot": a.severity == "high"})
            self.timeline.appendleft({**a.to_json(),
                                      "name": (E.get(a.entity).name if E.get(a.entity) else a.entity)})
            self.stats["actions"] += 1
            if a.severity == "high":
                self.stats["high_actions"] += 1
            verb = {"monitor": "Monitoring", "step_up": "Step-up auth for",
                    "restrict": "Restricting", "quarantine": "Quarantining",
                    "suspend": "Suspending"}[a.kind]
            nm = E.get(a.entity).name if E.get(a.entity) else a.entity
            gate = "" if a.approved else " (awaiting approval)"
            self._logline(f"{verb} {nm} [{a.tier}]{gate}. {a.reason}")

        dur = (time.perf_counter() - t0) * 1000
        for b in self.beats.values():
            b["latency_ms"] = round(dur / max(1, len(self.beats)), 2)

    def _scenario_label(self) -> Optional[str]:
        sims = self.gen.simulations()
        if not sims:
            return None
        return sims[0]["label"] if len(sims) == 1 else f"{len(sims)} simulations"

    def _logline(self, text: str) -> None:
        self.log.appendleft({"ts": time.strftime("%H:%M:%S"), "tick": self.tick, "text": text})

    # ---------------------------------------------------------------- reads
    def agents_snapshot(self) -> List[Dict[str, Any]]:
        poisoned = self.gen.poisoned_agents
        out = []
        for aid, dom in AGENT_SPECS:
            s = self.last_scores.get(aid)
            info = AGENT_INFO[aid]
            victim = poisoned.get(aid)
            out.append({
                "id": aid, "domain": dom, "title": info["title"], "short": info["short"],
                "detector": info["detector"], "watches": info["watches"],
                "features": info["features"], "placement": info["placement"],
                "mitre": info["mitre"],
                "score": round(s.score, 3) if s else 0.0,
                "confidence": round(s.confidence, 3) if s else 0.0,
                "reliability": round(self.fusion.reliabilities.get(aid, 1.0), 3),
                "spark": list(self.spark[aid]),
                "poisoned": victim is not None,
                "poisoned_for": victim,
                "subject": s.entity if s else None,
                "subject_name": (E.get(s.entity).name if s and E.get(s.entity) else None),
                "top_features": s.top_features if s else [],
                "beat": self.beats[aid],
            })
        return out

    def snapshot(self) -> Dict[str, Any]:
        top = max(self.verdicts.values(), key=lambda v: v.risk, default=None)
        verdict = top.to_json() if top else {
            "entity": "—", "risk": 0.0, "tier": "Normal", "conflict": 0.0,
            "belief_mal": 0.0, "alarm": False, "contributors": []}
        if top and E.get(top.entity):
            verdict["name"] = E.get(top.entity).name
            verdict["host"] = E.get(top.entity).host
        return {
            "tick": self.tick,
            "simulations": self.gen.simulations(),
            "scenario": self._scenario_label(),
            "events_seen": self.events_seen,
            "agents": self.agents_snapshot(),
            "verdict": verdict,
            "timeline": list(self.timeline)[:16],
            "log": list(self.log)[:18],
            "pulses": self.flow_pulses,
            "contained": self.enterprise.contained,
            "budget": {"beta": self.response.beta, "mu": round(self.response.mu, 3)},
            "stats": dict(self.stats),
            "open_incidents": len(self.incidents.open_for_entity),
            "population": len(E.all_entities()),
        }

    def entities_snapshot(self) -> List[Dict[str, Any]]:
        out = []
        for ent in E.all_entities():
            r = self.entity_risk.get(ent.uid, {"risk": 0.0, "tier": "Normal",
                                               "conflict": 0.0, "alarm": False})
            d = ent.to_json()
            d.update(r)
            d["contained"] = self.enterprise.contained.get(ent.uid)
            d["incidents"] = self.incidents.for_entity(ent.uid)
            d["active_kinds"] = self.gen.active_kinds_for(ent.uid)
            out.append(d)
        return out
