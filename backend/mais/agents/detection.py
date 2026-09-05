"""
detection.py — the specialised detection agents.

A DetectionAgent subscribes only to its own telemetry domain, wraps a
lightweight detector, and publishes a Score for the entity it just observed.
Several agents run at once (network, host, identity, file/device), which is
what gives the fusion agent independent evidence to combine.

The agent also honours a `poison` hook: when the generator marks this agent as
poisoned (Scenario B), it deliberately reports the OPPOSITE verdict (benign,
high confidence). The fusion agent is what catches this — the agent itself has
no idea it has been subverted, exactly as a compromised sensor would behave.
"""
from __future__ import annotations
import time
from typing import Optional, Callable, Dict, List
from ..agent_base import Agent
from ..contracts import Event, Score
from ..detectors import BehaviourDetector


# which event kinds belong to which agent
DOMAIN_KINDS = {
    "network": {"flow"},
    "host": {"proc"},
    "identity": {"logon"},
    "file": {"file_write", "usb"},
}

# feature emphasis per domain (features most indicative of the domain's threat)
DOMAIN_WEIGHTS = {
    "network": {"bytes_out": 1.4, "dst_novelty": 1.2},
    "host": {"proc_rare": 1.3, "hosts_touched": 1.35},
    "identity": {"fail_count": 1.3, "geo_novelty": 1.2, "logon_hour": 1.0},
    "file": {"file_sensitivity": 1.3, "usb_bytes": 1.4},
}


class DetectionAgent(Agent):
    def __init__(self, agent_id: str, domain: str,
                 poison_check: Optional[Callable[[], dict]] = None):
        self.agent_id = agent_id
        self.domain = domain
        self.reliability = 1.0
        self.detector = BehaviourDetector(agent_id, DOMAIN_WEIGHTS.get(domain))
        # every event this agent observed this tick, keyed by subject: an agent
        # watching a whole department must report on each person it saw, not just
        # the last event that happened to arrive
        self._pending: Dict[str, Event] = {}
        self._out: List[Score] = []
        self._poison_check = poison_check

    # perceive: keep this tick's latest event per subject for this domain
    def perceive(self, ev: Event) -> None:
        if ev.domain == self.domain and ev.kind in DOMAIN_KINDS[self.domain]:
            self._pending[ev.entity] = ev

    def warm(self, ev: Event) -> None:
        """Fold a benign event into the baseline without emitting a score."""
        if ev.domain == self.domain and ev.kind in DOMAIN_KINDS[self.domain]:
            self.detector.learn(ev.entity, ev.features)

    def reason(self) -> None:
        self._out = []
        pending, self._pending = self._pending, {}
        for ev in pending.values():
            self._out.append(self._score_one(ev))

    def _score_one(self, ev: Event) -> Score:
        s, conf, top = self.detector.score(ev.entity, ev.features)

        # If this agent has been subverted for THIS entity, it flips to a
        # confident 'benign' verdict — the signature of a poisoned sensor. It has
        # no idea it is lying; only the fusion layer can tell.
        poisoned = False
        if self._poison_check:
            victims = self._poison_check() or {}
            poisoned = victims.get(self.agent_id) == ev.entity
        if poisoned:
            s = 0.03
            conf = 0.95
            top = [("(suppressed)", 1.0)]

        return Score(ts=time.time(), agent_id=self.agent_id,
                     domain=self.domain, entity=ev.entity,
                     score=s, confidence=conf, top_features=top)

    def act(self) -> List[Score]:
        return self._out
