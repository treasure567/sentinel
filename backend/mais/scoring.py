"""
scoring.py — normalised insider-risk score and the four-tier risk ladder.

The fused belief in 'malicious' is combined with two bonuses that reflect the
report's scoring model:
  * a cross-domain correlation bonus — evidence that co-occurs across distinct
    telemetry domains (identity AND file AND network) is far more indicative of
    a real attack than the same number of flags in one domain;
  * a temporal-escalation bonus — a rising, self-reinforcing set of agents
    firing captures the trajectory of an insider incident.

The result is squashed to 0..1 and mapped to Normal / Elevated / High / Critical.
"""
from __future__ import annotations
from typing import List, Tuple

# tier cut-points (justified defaults; tune in defaults.py)
TIERS = [
    (0.75, "Critical"),
    (0.55, "High"),
    (0.35, "Elevated"),
    (0.00, "Normal"),
]


def risk_and_tier(belief_mal: float, scores: List) -> Tuple[float, str]:
    # how many distinct domains are currently implicating this entity, and how hard
    hot = [s for s in scores if s.score >= 0.5]
    domains = {s.domain for s in hot}
    corr_bonus = 0.06 * max(0, len(domains) - 1)          # cross-domain coincidence
    esc_bonus = 0.04 * max(0, len(hot) - 1)               # multiple agents escalating
    risk = min(1.0, belief_mal + corr_bonus + esc_bonus)
    for cut, name in TIERS:
        if risk >= cut:
            return risk, name
    return risk, "Normal"
