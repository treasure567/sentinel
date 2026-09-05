"""
incidents.py — the case store.

When an entity's risk rises out of Normal, an Incident (a case) is opened for it.
While the incident is live it accumulates everything an analyst needs to review
later: the raw event trace, the evidence each detection agent contributed, the
fused belief and conflict mass over time, every response action taken, the MITRE
techniques observed, and whether a conflict alarm (agent poisoning) fired.

Incidents are what the Incidents list and the incident-detail drill-down read.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
import time
import itertools

_counter = itertools.count(1001)


@dataclass
class TraceRow:
    ts: float
    tick: int
    domain: str
    kind: str
    detail: str            # human-readable summary of the event
    score: float           # the agent score this event produced
    features: Dict[str, float] = field(default_factory=dict)


@dataclass
class Incident:
    id: str
    entity: str
    opened_ts: float
    opened_tick: int
    status: str = "Open"                 # Open | Contained | Closed
    peak_risk: float = 0.0
    peak_tier: str = "Normal"
    max_conflict: float = 0.0
    alarm: bool = False
    poisoned_agent: Optional[str] = None
    updated_ts: float = 0.0
    updated_tick: int = 0
    scenario: Optional[str] = None
    trace: List[TraceRow] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    risk_series: List[float] = field(default_factory=list)
    conflict_series: List[float] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    agent_evidence: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "id": self.id, "entity": self.entity, "status": self.status,
            "opened_ts": self.opened_ts, "updated_ts": self.updated_ts,
            "peak_risk": round(self.peak_risk, 3), "peak_tier": self.peak_tier,
            "max_conflict": round(self.max_conflict, 3), "alarm": self.alarm,
            "poisoned_agent": self.poisoned_agent, "scenario": self.scenario,
            "n_events": len(self.trace), "n_actions": len(self.actions),
            "mitre": self.mitre,
        }

    def detail(self) -> Dict[str, Any]:
        d = self.summary()
        d["trace"] = [asdict(r) for r in self.trace][-60:]
        d["actions"] = self.actions[-40:]
        d["risk_series"] = [round(x, 3) for x in self.risk_series][-80:]
        d["conflict_series"] = [round(x, 3) for x in self.conflict_series][-80:]
        d["agent_evidence"] = self.agent_evidence
        return d


DETAIL = {
    "logon": lambda f: (f"Logon at {int(f.get('logon_hour',0)):02d}:00, "
                        f"geo-novelty {f.get('geo_novelty',0):.2f}, "
                        f"{int(f.get('fail_count',0))} failed attempts"),
    "proc": lambda f: f"Process launch, rarity {f.get('proc_rare',0):.2f}",
    "file_write": lambda f: (f"File write, sensitivity {f.get('file_sensitivity',0):.2f}, "
                             f"USB {f.get('usb_bytes',0):.2f}"),
    "flow": lambda f: (f"Outbound flow, volume {f.get('bytes_out',0):.2f}, "
                       f"dst-novelty {f.get('dst_novelty',0):.2f}"),
}


class IncidentStore:
    OPEN_TIER = {"High", "Critical"}          # a case opens only on High+ ...
    OPEN_STREAK = 2                            # ... sustained for 2 ticks (no blips)
    KEEP_TIER = {"Elevated", "High", "Critical"}   # ... but stays open through Elevated
    CLOSE_GRACE = 3                            # close only after Normal persists

    def __init__(self) -> None:
        self.by_id: Dict[str, Incident] = {}
        self.open_for_entity: Dict[str, str] = {}     # entity -> live incident id
        self.order: List[str] = []                    # newest last
        self._streak: Dict[str, int] = {}             # consecutive High+ ticks
        self._cooldown: Dict[str, int] = {}           # consecutive Normal ticks while open

    def _open(self, entity: str, tick: int, scenario) -> Incident:
        iid = f"INC-{next(_counter)}"
        inc = Incident(id=iid, entity=entity, opened_ts=time.time(),
                       opened_tick=tick, scenario=scenario)
        self.by_id[iid] = inc
        self.open_for_entity[entity] = iid
        self.order.append(iid)
        return inc

    def record_event(self, entity: str, tick: int, domain: str, kind: str,
                     features: Dict[str, float], score: float) -> None:
        iid = self.open_for_entity.get(entity)
        if not iid:
            return
        inc = self.by_id[iid]
        detail = DETAIL.get(kind, lambda f: kind)(features)
        inc.trace.append(TraceRow(time.time(), tick, domain, kind, detail,
                                  round(score, 3), {k: round(v, 3) for k, v in features.items()}))

    def update_from_verdict(self, verdict, tick: int, scenario) -> None:
        entity = verdict.entity
        live = self.open_for_entity.get(entity)

        # count how many distinct agents are actively implicating this entity;
        # a genuine incident is corroborated across agents, benign noise is not
        corroborating = sum(1 for _a, _w, s in verdict.contributors if s >= 0.5)

        # track how long this entity has been High+ AND corroborated (no blips)
        if verdict.tier in self.OPEN_TIER and corroborating >= 2:
            self._streak[entity] = self._streak.get(entity, 0) + 1
        else:
            self._streak[entity] = 0

        should_be_open = live is not None and verdict.tier in self.KEEP_TIER
        should_open = live is None and self._streak.get(entity, 0) >= self.OPEN_STREAK

        if should_open or should_be_open:
            inc = self.by_id[live] if live else self._open(entity, tick, scenario)
            self._cooldown[entity] = 0
            inc.scenario = inc.scenario or scenario
            if verdict.risk >= inc.peak_risk:
                inc.peak_risk = verdict.risk
                inc.peak_tier = verdict.tier
            inc.max_conflict = max(inc.max_conflict, verdict.conflict)
            inc.alarm = inc.alarm or verdict.alarm
            inc.updated_ts = time.time()
            inc.updated_tick = tick
            inc.risk_series.append(verdict.risk)
            inc.conflict_series.append(verdict.conflict)
            for aid, w, s in verdict.contributors:
                inc.agent_evidence[aid] = {"reliability": round(w, 3), "score": round(s, 3)}
                if verdict.alarm and w <= 0.1:
                    inc.poisoned_agent = aid
        elif live:
            # risk fell out of the keep band; close only after a grace period so
            # the incident does not flap on a single quiet tick
            self._cooldown[entity] = self._cooldown.get(entity, 0) + 1
            inc = self.by_id[live]
            if self._cooldown[entity] >= self.CLOSE_GRACE:
                inc.status = "Contained" if inc.actions else "Closed"
                del self.open_for_entity[entity]
                self._cooldown[entity] = 0

    def record_action(self, action, tick: int) -> None:
        iid = self.open_for_entity.get(action.entity)
        if not iid:
            return
        inc = self.by_id[iid]
        aj = action.to_json()
        aj["tick"] = tick
        inc.actions.append(aj)
        if action.mitre and action.mitre not in inc.mitre:
            inc.mitre.append(action.mitre)
        if action.kind in ("quarantine", "suspend") and action.approved:
            inc.status = "Contained"

    # ---- reads ----
    MIN_EVIDENCE = 8      # a shown case must have accumulated real trace evidence

    def _visible(self, inc: "Incident") -> bool:
        # a genuine multi-stage incident accumulates dozens of trace rows and
        # drives real containment; a transient benign blip does neither
        return len(inc.trace) >= self.MIN_EVIDENCE and len(inc.actions) >= 2

    def list(self) -> List[Dict[str, Any]]:
        return [self.by_id[i].summary() for i in reversed(self.order)
                if self._visible(self.by_id[i])]

    def get(self, iid: str) -> Optional[Dict[str, Any]]:
        inc = self.by_id.get(iid)
        return inc.detail() if inc else None

    def for_entity(self, entity: str) -> List[Dict[str, Any]]:
        return [self.by_id[i].summary() for i in reversed(self.order)
                if self.by_id[i].entity == entity and self._visible(self.by_id[i])]
