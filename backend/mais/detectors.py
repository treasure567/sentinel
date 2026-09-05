"""
detectors.py — lightweight, fast anomaly detectors (numpy only).

Each detector maintains a per-entity running profile (mean and variance of each
feature) and scores a new observation by how far it deviates from that entity's
OWN normal behaviour — the user-and-entity-behaviour-analytics principle from
the report: anomaly is defined relative to the individual, not the population.

The deviation is a standardised (z-score) distance, squashed to 0..1. Because
the score is a sum of per-feature contributions, the detector can name the
features that drove it (`top_features`), which is what the explanation layer
surfaces to the analyst.

This is deliberately transparent and dependency-free. `detector.score(...)`
is the interface the detection agents wrap; a scikit-learn model exposing the
same method could be dropped in unchanged.
"""
from __future__ import annotations
import numpy as np
from typing import Dict, List, Tuple


class RunningProfile:
    """
    Online mean/variance per feature, per entity, with a bounded (frozen) sample
    count. Once warmed up, the baseline updates only very slowly — a small
    exponential nudge — so that a sustained attack is NOT quietly absorbed into
    "normal". This is the report's decay-limited baseline: it tracks legitimate
    drift but resists an insider trying to normalise malicious behaviour.
    """
    FREEZE_N = 30          # after this many samples the mean adapts slowly, not 1/n
    ALPHA = 0.02           # slow exponential adaptation rate once frozen

    def __init__(self) -> None:
        self.n = 0
        self.mean: Dict[str, float] = {}
        self.m2: Dict[str, float] = {}
        self.std_cache: Dict[str, float] = {}

    def update(self, feats: Dict[str, float]) -> None:
        self.n += 1
        for k, x in feats.items():
            if self.n <= self.FREEZE_N:
                mean = self.mean.get(k, 0.0)
                delta = x - mean
                mean += delta / self.n
                self.mean[k] = mean
                self.m2[k] = self.m2.get(k, 0.0) + delta * (x - mean)
            else:
                # slow exponential update; keeps the baseline near true normal
                self.mean[k] = (1 - self.ALPHA) * self.mean.get(k, x) + self.ALPHA * x

    def std(self, k: str) -> float:
        neff = min(self.n, self.FREEZE_N)
        if neff < 2:
            return 1.0
        var = self.m2.get(k, 0.0) / (neff - 1)
        return float(max(var ** 0.5, 1e-3))


class BehaviourDetector:
    """
    A statistical behaviour detector for one domain.

    `learn_only=True` folds an observation into the baseline without scoring it
    (used to warm up the profiles on benign traffic). Otherwise `score` returns
    (score, confidence, top_features).
    """
    def __init__(self, name: str, weights: Dict[str, float] | None = None):
        self.name = name
        self.profiles: Dict[str, RunningProfile] = {}
        # optional per-feature emphasis (some features matter more)
        self.weights = weights or {}

    def _profile(self, entity: str) -> RunningProfile:
        if entity not in self.profiles:
            self.profiles[entity] = RunningProfile()
        return self.profiles[entity]

    def learn(self, entity: str, feats: Dict[str, float]) -> None:
        self._profile(entity).update(feats)

    def score(self, entity: str, feats: Dict[str, float]
              ) -> Tuple[float, float, List[Tuple[str, float]]]:
        prof = self._profile(entity)
        contribs: List[Tuple[str, float]] = []
        total = 0.0
        for k, x in feats.items():
            mean = prof.mean.get(k, x)
            z = abs(x - mean) / prof.std(k)
            w = self.weights.get(k, 1.0)
            c = w * z
            contribs.append((k, c))
            total += c * c
        # standardised distance -> 0..1 with a KNEE: normal jitter (a couple of
        # standard deviations of ordinary variation) sits below the knee and
        # scores near zero, so benign traffic does not trip the detector; only a
        # genuinely large, multi-feature deviation climbs toward 1.
        dist = float(np.sqrt(total))
        KNEE, SCALE = 3.2, 14.0
        excess = max(0.0, dist - KNEE)
        score = float(1.0 - np.exp(-(excess ** 2) / SCALE))
        # fold this observation into the baseline ONLY if it looks benign; a
        # strongly anomalous observation is not absorbed as "normal" (this is
        # what stops a sustained attack from decaying to baseline).
        if score < 0.15:
            prof.update(feats)
        # confidence grows with how much history we have and how sharp the signal is
        conf = float(np.clip(0.4 + 0.06 * prof.n + 0.4 * score, 0, 0.98))
        contribs.sort(key=lambda t: t[1], reverse=True)
        # normalise contributions to 0..1 for display
        mx = max((c for _, c in contribs), default=1.0) or 1.0
        top = [(k, float(c / mx)) for k, c in contribs[:3]]
        return score, conf, top
