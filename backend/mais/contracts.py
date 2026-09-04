"""
contracts.py — the shared vocabulary of the whole system (the message ontology).

Everything that crosses a component boundary is one of these dataclasses, and
these are the ONLY objects placed on the bus. Detection agents publish `Score`;
the fusion agent publishes `Verdict`; the response agent publishes `Action`;
the generator publishes `Event`. Keeping this file small and stable is what
lets every part of the system be built and tested independently.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Tuple, Dict, Any


@dataclass
class Event:
    """Raw telemetry emitted by the generator, consumed by detection agents."""
    ts: float                       # unix time
    domain: str                     # 'network' | 'host' | 'identity' | 'file'
    entity: str                     # the user/host this concerns, e.g. 'user:alice'
    kind: str                       # 'flow' | 'logon' | 'proc' | 'file_write' | 'usb'
    features: Dict[str, float] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Score:
    """A per-entity threat judgement emitted by a single detection agent."""
    ts: float
    agent_id: str                   # 'net-flow', 'host-seq', 'id-logon', ...
    domain: str
    entity: str
    score: float                    # 0..1 threat score
    confidence: float               # 0..1 calibrated confidence
    top_features: List[Tuple[str, float]] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        d["top_features"] = [[n, round(float(v), 3)] for n, v in self.top_features]
        d["score"] = round(float(self.score), 3)
        d["confidence"] = round(float(self.confidence), 3)
        return d


@dataclass
class Verdict:
    """The fused, conflict-aware risk assessment emitted by the fusion agent."""
    ts: float
    entity: str
    risk: float                     # 0..1 normalised insider-risk score
    tier: str                       # 'Normal' | 'Elevated' | 'High' | 'Critical'
    conflict: float                 # conflict mass K, 0..1
    belief_mal: float               # fused belief in 'malicious'
    contributors: List[Tuple[str, float, float]] = field(default_factory=list)
    #                    (agent_id, discounted_weight, raw_score)
    alarm: bool = False             # True when conflict K exceeds threshold

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        d["contributors"] = [[a, round(float(w), 3), round(float(s), 3)]
                             for a, w, s in self.contributors]
        for k in ("risk", "conflict", "belief_mal"):
            d[k] = round(float(d[k]), 3)
        return d


@dataclass
class Action:
    """A proportionate, bounded response emitted by the response agent."""
    ts: float
    entity: str
    kind: str                       # 'monitor'|'step_up'|'restrict'|'quarantine'|'suspend'
    severity: str                   # 'low' | 'high'
    approved: bool                  # gate result
    mu: float                       # current Lagrange multiplier (budget pressure)
    reason: str                     # plain-language explanation
    mitre: str = ""                 # e.g. 'T1078 Valid Accounts'
    tier: str = ""                  # the risk tier that triggered it

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        d["mu"] = round(float(self.mu), 3)
        return d


# Topics used on the bus.
TOPIC_EVENT = "event"
TOPIC_SCORE = "score"
TOPIC_VERDICT = "verdict"
TOPIC_ACTION = "action"
TOPIC_ALARM = "alarm"      # a lightweight UI signal when a conflict alarm fires
TOPIC_LOG = "log"          # human-readable log lines for the dashboard ticker
