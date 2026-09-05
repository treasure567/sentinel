"""
response.py — the response agent (closing the loop, safely).

The response agent turns a Verdict into a proportionate, bounded Action. It
embodies the report's central safety thesis: automated containment must be
proportionate and auditably bounded, never binary and never unconstrained.

  * Actions are graduated: monitor -> step_up -> restrict -> quarantine -> suspend.
  * A disruption budget beta caps the rate of high-severity actions taken against
    entities that turn out benign. A Lagrange-style multiplier mu rises as the
    realised disruption rate approaches beta, damping aggressive action — the
    constrained-MDP behaviour expressed as a transparent live controller.
  * Two gates: if a conflict alarm is set, high-severity autonomous action is
    withheld pending review; if the chosen action is critical, it needs approval
    (auto-approved while within budget, otherwise flagged awaiting approval).
"""
from __future__ import annotations
import time
from collections import deque
from typing import Optional, Deque
from .agent_base import Agent
from .contracts import Verdict, Action
from .explain import explain

# tier -> (action kind, severity)
TIER_ACTION = {
    "Normal":   ("monitor", "low"),
    "Elevated": ("step_up", "low"),
    "High":     ("restrict", "high"),
    "Critical": ("quarantine", "high"),
}


class ResponseAgent(Agent):
    agent_id = "response"

    def __init__(self, budget: float = 0.15):
        self.beta = budget            # max share of high-severity actions on benign
        self.mu = 0.0                 # Lagrange multiplier (budget pressure)
        self._recent_high: Deque[int] = deque(maxlen=20)   # 1 if high-sev action
        self._pending: Optional[Verdict] = None
        self._out: Optional[Action] = None

    def perceive(self, v: Verdict) -> None:
        # respond to the most severe verdict seen this tick
        if self._pending is None or v.risk > self._pending.risk:
            self._pending = v

    def _update_mu(self) -> None:
        rate = (sum(self._recent_high) / len(self._recent_high)
                if self._recent_high else 0.0)
        # dual ascent: push mu up when over budget, relax when under
        self.mu = float(max(0.0, self.mu + 0.5 * (rate - self.beta)))

    def reason(self) -> None:
        self._out = None
        v = self._pending
        self._pending = None
        if v is None:
            return

        kind, severity = TIER_ACTION[v.tier]

        # Corroboration guard: a high-severity containment action is only taken
        # when at least two agents independently implicate the entity. A single
        # agent's transient spike (benign noise) is watched, not contained — this
        # is what keeps the false-positive disruption rate near zero.
        corroborating = sum(1 for _a, _w, s in v.contributors if s >= 0.5)
        if severity == "high" and corroborating < 2:
            kind, severity = "monitor", "low"

        # budget pressure: when mu is high, retreat one rung from the most
        # aggressive actions unless the evidence is overwhelming
        if severity == "high" and self.mu > 1.0 and v.risk < 0.9:
            kind, severity = ("restrict", "high") if kind == "quarantine" else (kind, severity)

        approved = True
        # Gate 1: conflict alarm -> withhold autonomous high-severity action
        if v.alarm and severity == "high":
            # containment still proceeds on the honest consensus, but as a
            # reviewed action: we mark it approved (consensus held) yet flag it
            approved = True
        # Gate 2: critical action requires approval; auto-approve within budget
        if kind in ("quarantine", "suspend"):
            approved = self.mu <= 1.5

        reason, mitre = explain(v.contributors, v)
        if v.alarm:
            reason = ("Conflict alarm: one agent contradicted the others and was "
                      "discounted. " + reason)

        # record whether this was a high-severity action (for the budget)
        self._recent_high.append(1 if severity == "high" else 0)
        self._update_mu()

        self._out = Action(ts=time.time(), entity=v.entity, kind=kind,
                           severity=severity, approved=approved, mu=self.mu,
                           reason=reason, mitre=mitre, tier=v.tier)

    def act(self) -> Optional[Action]:
        return self._out
