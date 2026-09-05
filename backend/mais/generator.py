"""
generator.py — synthetic telemetry for the simulated department, and the
attack simulations that run on top of it.

Baseline: all thirty members of the department go about normal work, each
against their own behavioural profile, so "normal" differs per person.

On top of that an analyst can start one or more SIMULATIONS. A simulation is a
named playbook aimed at one entity, made of one or more activity KINDS:

    identity   odd-hour logons, failed authentication, unfamiliar location
    file       sensitive-file access and large writes to removable media
    network    outbound volume spikes to a never-seen destination
    host       rare process execution, persistence, beaconing
    lateral    movement toward other hosts using valid credentials

Playbooks combine them into a story (exfiltration, credential abuse, lateral
movement, sabotage), and any playbook can be run with a poisoned agent so the
fusion layer's conflict alarm can be demonstrated on it. Because the analyst
picks the target and the kinds, no two runs need look alike.
"""
from __future__ import annotations
import time
import hashlib
import itertools
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .contracts import Event
from . import entities as E

KINDS = ["identity", "file", "network", "host", "lateral"]

# playbook -> (label, kinds in the order they switch on, description)
PLAYBOOKS: Dict[str, dict] = {
    "exfiltration": dict(
        label="Data exfiltration",
        kinds=["identity", "file", "network"],
        story="Out-of-hours access, sensitive files staged to removable media, then a large "
              "outbound transfer to an unfamiliar host."),
    "credential_abuse": dict(
        label="Credential abuse",
        kinds=["identity", "host"],
        story="Repeated failed authentication from an unusual source, then a successful logon "
              "and unfamiliar processes running under the account."),
    "lateral_movement": dict(
        label="Lateral movement",
        kinds=["identity", "lateral", "host"],
        story="A valid account is used to reach hosts it has never touched, installing "
              "persistence as it goes."),
    "sabotage": dict(
        label="Sabotage / destruction",
        kinds=["host", "file"],
        story="Unfamiliar processes deleting and rewriting departmental records."),
    "slow_drip": dict(
        label="Low-and-slow exfiltration",
        kinds=["file", "network"],
        story="Small, patient transfers designed to stay under volume thresholds."),
}

_sim_ids = itertools.count(1)


@dataclass
class Simulation:
    id: int
    uid: str                       # target entity
    playbook: str
    kinds: List[str]
    intensity: str = "medium"      # low | medium | high
    poison_agent: Optional[str] = None   # agent id to subvert, or None
    started_tick: int = 0
    label: str = ""
    story: str = ""

    def to_json(self) -> dict:
        e = E.get(self.uid)
        return {"id": self.id, "uid": self.uid, "name": e.name if e else self.uid,
                "host": e.host if e else "", "playbook": self.playbook,
                "label": self.label, "story": self.story, "kinds": self.kinds,
                "intensity": self.intensity, "poison_agent": self.poison_agent,
                "started_tick": self.started_tick}


_INTENSITY = {"low": 0.55, "medium": 0.8, "high": 0.97}


class Generator:
    """Emits the department's telemetry, one tick at a time."""

    def __init__(self, seed: int = 7):
        self.rng = np.random.default_rng(seed)
        self.t = 0
        self.sims: Dict[int, Simulation] = {}
        self.baseline: Dict[str, Dict[str, float]] = {}
        for e in E.all_entities():
            # a STABLE per-person seed. Python's built-in hash() is salted per
            # process, which would make every run of the system different and
            # every tuning decision unreproducible.
            stable = int(hashlib.sha256(e.uid.encode()).hexdigest()[:8], 16)
            r = np.random.default_rng(stable)
            # each person's own normal: working hour, novelty tolerance, volumes
            start = int(e.normal_hours.split("-")[0].split(":")[0])
            self.baseline[e.uid] = {
                "logon_hour": start + r.uniform(0, 1.5),
                "geo_novelty": 0.04 + r.uniform(0, 0.04),
                "fail_count": 0.15 + r.uniform(0, 0.25),
                "file_sensitivity": 0.12 + r.uniform(0, 0.25),
                "usb_bytes": 0.04 + r.uniform(0, 0.05),
                "bytes_out": 0.12 + r.uniform(0, 0.2),
                "dst_novelty": 0.06 + r.uniform(0, 0.08),
                "proc_rare": 0.07 + r.uniform(0, 0.08),
                "hosts_touched": 0.05 + r.uniform(0, 0.05),
            }

    # ---------------------------------------------------------- simulations
    def start_simulation(self, uid: str, playbook: str = "exfiltration",
                         kinds: Optional[List[str]] = None, intensity: str = "medium",
                         poison_agent: Optional[str] = None) -> Simulation:
        pb = PLAYBOOKS.get(playbook, PLAYBOOKS["exfiltration"])
        use_kinds = [k for k in (kinds or pb["kinds"]) if k in KINDS] or pb["kinds"]
        sim = Simulation(id=next(_sim_ids), uid=uid, playbook=playbook,
                         kinds=list(use_kinds), intensity=intensity,
                         poison_agent=poison_agent, started_tick=self.t,
                         label=pb["label"] if not kinds else "Custom simulation",
                         story=pb["story"] if not kinds else
                               "Analyst-defined activity: " + ", ".join(use_kinds) + ".")
        self.sims[sim.id] = sim
        return sim

    def stop_simulation(self, sim_id: int) -> bool:
        return self.sims.pop(sim_id, None) is not None

    def stop_all(self) -> None:
        self.sims.clear()

    def active_kinds_for(self, uid: str) -> List[str]:
        ks: List[str] = []
        for s in self.sims.values():
            if s.uid == uid:
                for k in s.kinds:
                    if k not in ks:
                        ks.append(k)
        return ks

    @property
    def poisoned_agents(self) -> Dict[str, str]:
        """agent_id -> uid of the entity whose reporting is being suppressed."""
        out = {}
        for s in self.sims.values():
            if s.poison_agent and (self.t - s.started_tick) >= 2:
                out[s.poison_agent] = s.uid
        return out

    def simulations(self) -> List[dict]:
        return [s.to_json() for s in self.sims.values()]

    def warm_tick(self) -> List[Event]:
        """
        One cycle of purely normal activity for EVERY person, used only to train
        the detectors' baselines before the system goes live. Sampling a random
        handful (as the live tick does) would leave most of the department with
        almost no history, and a detector with no history calls ordinary work
        anomalous — which is exactly how a monitoring system earns the distrust
        of the people it watches.
        """
        now = time.time()
        events: List[Event] = []
        for e in E.all_entities():
            events += self._normal_events(e, now)
        self.t += 1
        return events

    # ---------------------------------------------------------------- tick
    def tick(self) -> List[Event]:
        now = time.time()
        events: List[Event] = []
        # a slice of the department is active each tick
        pool = [e for e in E.all_entities() if not e.traffic_paused]
        if pool:
            k = min(len(pool), 5)
            for e in self.rng.choice(pool, size=k, replace=False):
                events += self._normal_events(e, now)
        # simulations layered on top
        for sim in list(self.sims.values()):
            e = E.get(sim.uid)
            if e is None or e.traffic_paused:
                continue
            events += self._sim_events(sim, e, now)
        self.t += 1
        return events

    # ------------------------------------------------------------ baseline
    def _normal_events(self, e: E.Entity, now: float) -> List[Event]:
        b = self.baseline[e.uid]
        r = self.rng
        uid = e.uid
        ev: List[Event] = []
        if r.random() < 0.5:
            ev.append(Event(now, "identity", uid, "logon", {
                "logon_hour": float(np.clip(b["logon_hour"] + r.normal(0, 0.6), 0, 23)),
                "geo_novelty": float(np.clip(b["geo_novelty"] + r.normal(0, 0.02), 0, 1)),
                "fail_count": float(max(0.0, r.normal(b["fail_count"], 0.2))),
            }))
        if r.random() < 0.5:
            ev.append(Event(now, "host", uid, "proc", {
                "proc_rare": float(np.clip(b["proc_rare"] + r.normal(0, 0.04), 0, 1)),
                "hosts_touched": float(np.clip(b["hosts_touched"] + r.normal(0, 0.03), 0, 1)),
            }))
        if r.random() < 0.45:
            ev.append(Event(now, "file", uid, "file_write", {
                "file_sensitivity": float(np.clip(b["file_sensitivity"] + r.normal(0, 0.05), 0, 1)),
                "usb_bytes": float(np.clip(b["usb_bytes"] + r.normal(0, 0.02), 0, 1)),
            }))
        if r.random() < 0.6:
            if e.isolated:
                # A quarantined host is not switched off — it is moved to a
                # restricted VLAN. The network agent still observes it; it simply
                # sees very little. Keeping the sensor reporting matters: an agent
                # that goes silent can no longer be checked against its peers.
                ev.append(Event(now, "network", uid, "flow", {
                    "bytes_out": float(max(0.0, r.normal(0.02, 0.01))),
                    "dst_novelty": float(max(0.0, r.normal(0.02, 0.01))),
                }))
            else:
                ev.append(Event(now, "network", uid, "flow", {
                    "bytes_out": float(np.clip(b["bytes_out"] + r.normal(0, 0.05), 0, 1)),
                    "dst_novelty": float(np.clip(b["dst_novelty"] + r.normal(0, 0.04), 0, 1)),
                }))
        return ev

    # ----------------------------------------------------------- simulation
    def _sim_events(self, sim: Simulation, e: E.Entity, now: float) -> List[Event]:
        """
        Stage the chosen kinds in over the first few ticks so the incident builds
        as a story, then sustain it. Isolation cuts the network arm — which is
        exactly what containment should look like on the dashboard.
        """
        dt = self.t - sim.started_tick
        hi = _INTENSITY.get(sim.intensity, 0.8)
        lo = max(0.35, hi - 0.18)
        r = self.rng
        uid = e.uid
        ev: List[Event] = []
        # each kind switches on a tick apart, in the playbook's order
        for i, kind in enumerate(sim.kinds):
            if dt < i:
                continue
            if kind == "identity":
                ev.append(Event(now, "identity", uid, "logon", {
                    "logon_hour": float(r.uniform(1, 4)),
                    "geo_novelty": float(r.uniform(lo, hi)),
                    "fail_count": float(r.uniform(3, 6) * (hi + 0.2)),
                }))
            elif kind == "file":
                ev.append(Event(now, "file", uid, "file_write", {
                    "file_sensitivity": float(r.uniform(lo, hi)),
                    "usb_bytes": float(r.uniform(lo, hi)),
                }))
            elif kind == "network":
                if e.isolated:
                    # containment holds: the exfiltration attempt no longer
                    # reaches the network, and the agent sees a quiet interface
                    ev.append(Event(now, "network", uid, "flow", {
                        "bytes_out": float(max(0.0, r.normal(0.02, 0.01))),
                        "dst_novelty": float(max(0.0, r.normal(0.02, 0.01))),
                    }))
                else:
                    ev.append(Event(now, "network", uid, "flow", {
                        "bytes_out": float(r.uniform(lo, hi)),
                        "dst_novelty": float(r.uniform(lo, hi)),
                    }))
            elif kind == "host":
                ev.append(Event(now, "host", uid, "proc", {
                    "proc_rare": float(r.uniform(lo, hi)),
                    "hosts_touched": float(r.uniform(0.2, 0.5)),
                }))
            elif kind == "lateral":
                ev.append(Event(now, "host", uid, "proc", {
                    "proc_rare": float(r.uniform(lo - 0.1, hi)),
                    "hosts_touched": float(r.uniform(lo, hi)),
                }))
                if not e.isolated:
                    ev.append(Event(now, "network", uid, "flow", {
                        "bytes_out": float(r.uniform(0.3, 0.55)),
                        "dst_novelty": float(r.uniform(lo, hi)),
                    }))
                else:
                    ev.append(Event(now, "network", uid, "flow", {
                        "bytes_out": float(max(0.0, r.normal(0.02, 0.01))),
                        "dst_novelty": float(max(0.0, r.normal(0.02, 0.01))),
                    }))
        return ev
