"""
fusion.py — the fusion & coordination agent (the analytical heart).

This is where the prototype improves on the base study (Audit-LLM), which
reconciles its agents through informal natural-language debate. Here the
independent judgements of the detection agents are combined with the
Dempster-Shafer theory of evidence, which (a) represents ignorance as a
first-class quantity and (b) yields an explicit CONFLICT MASS K that can be
monitored for signs of a subverted agent.

Pipeline per entity:
  1. reliability discounting — each agent whose recent scores diverge sharply
     from its own history is trusted less (a compromised sensor's tell);
  2. basic probability assignment — each discounted score becomes mass over
     {malicious, benign, ignorance};
  3. Dempster combination — masses are combined pairwise; the normalising
     conflict mass K is accumulated;
  4. alarm — if K exceeds a threshold, a conflict alarm is raised, the
     contradicting agent is sharply discounted, and the honest consensus is
     recombined so containment still proceeds.
"""
from __future__ import annotations
import time
from collections import defaultdict, deque
from typing import Dict, Deque, List, Optional, Tuple
from .agent_base import Agent
from .contracts import Score, Verdict
from . import scoring


class _AgentTrust:
    """
    One agent's recent history of judgements about one entity.

    Besides the running baseline used for reliability discounting, this detects a
    REGIME CHANGE: an agent that was reporting one thing about a person and now
    reports the opposite. A compromised sensor does not drift, it flips — and it
    then holds the new story, so the flip has to stay visible for more than the
    tick it happened on. Comparing the older half of the window with the recent
    half keeps it visible for as long as the subversion lasts.
    """
    WINDOW = 16

    def __init__(self) -> None:
        self.hist: Deque[float] = deque(maxlen=self.WINDOW)

    def observe(self, s: float) -> None:
        self.hist.append(s)

    def baseline(self) -> float:
        return sum(self.hist) / len(self.hist) if self.hist else 0.0

    def reversal(self) -> float:
        """0 = consistent, ->1 = the agent has reversed its position."""
        n = len(self.hist)
        if n < 6:
            return 0.0
        half = n // 2
        older = list(self.hist)[:half]
        recent = list(self.hist)[half:]
        return abs(sum(older) / len(older) - sum(recent) / len(recent))


class FusionAgent(Agent):
    agent_id = "fusion"

    def __init__(self, conflict_threshold: float = 0.28):
        self.tau_k = conflict_threshold
        self.trust: Dict[tuple, _AgentTrust] = defaultdict(_AgentTrust)
        # latest score per (entity, agent_id), with a short memory so evidence
        # from different domains can be fused even though it arrives at
        # different ticks
        # entity -> agent_id -> (Score, tick_it_arrived).  Evidence expires: an
        # agent that has not spoken about this entity recently contributes
        # nothing rather than a stale opinion, which is what stops a mixed-age
        # evidence set from manufacturing conflict that nobody actually asserted.
        self._latest: Dict[str, Dict[str, tuple]] = defaultdict(dict)
        self.EVIDENCE_TTL = 6        # ticks after which evidence is dropped entirely
        self._tick = 0
        self._inbox: List[Score] = []
        self._out: List[Verdict] = []
        self.reliabilities: Dict[str, float] = {}   # for the dashboard
        self._conflict_streak: Dict[str, int] = defaultdict(int)
        self.reversals: Dict[str, Dict[str, float]] = {}
        self.dissent_streaks: Dict[str, Dict[str, int]] = {}
        # (agent, entity) -> consecutive ticks this agent has dissented from a
        # clear majority about that entity
        self._dissent: Dict[tuple, int] = defaultdict(int)
        # how long this entity has been firmly implicated by the majority
        self._established: Dict[str, int] = defaultdict(int)
        self.ESTABLISHED_MIN = 4
        self.DISSENT_STREAK = 3
        self.ALARM_STREAK = 3       # conflict must persist to be a real alarm

    # perceive: collect scores arriving this tick
    def perceive(self, s: Score) -> None:
        self._inbox.append(s)

    def _discount(self, s: Score) -> float:
        """
        Reliability r in (0,1]: high when the agent's confidence is high AND its
        current judgement is consistent with what that same agent has recently
        been saying ABOUT THIS SAME ENTITY; low when it reverses itself sharply
        and suddenly, which is the signature of a subverted sensor.

        The history is kept per (agent, entity) deliberately. An agent watching a
        department of thirty people is *supposed* to score most of them near zero
        and one of them near one; judged against a single pooled history, a
        correct detection would look like a deviation and the honest agent would
        be punished for doing its job. Consistency only means anything relative
        to the same subject.
        """
        key = (s.agent_id, s.entity)
        t = self.trust[key]
        if len(t.hist) < 3:                 # not enough history to judge yet
            t.observe(s.score)
            return float(max(0.05, s.confidence))
        base = t.baseline()
        divergence = abs(s.score - base)    # a sudden reversal about this entity
        t.observe(s.score)
        r = s.confidence * (1.0 - min(1.0, 0.9 * divergence))
        return float(max(0.05, r))

    @staticmethod
    def _bpa(score: float, r: float) -> Tuple[float, float, float]:
        """
        Discounted score -> mass over (malicious, benign, ignorance).

        Uses a deadzone so that only a genuinely assertive judgement commits
        mass to a singleton; a middling score is treated as *ignorance*, not as
        confident innocence. This is what keeps honest agents that simply are
        not firing from generating spurious conflict, while a poisoned agent
        that confidently asserts 'benign' during an attack still commits strong
        benign mass and so shows up as conflict.
        """
        # Benign assertions are deliberately weaker than malicious ones. In this
        # domain the two are not symmetric: seeing malicious activity is strong
        # evidence of it, whereas *not* seeing anything is weak evidence of
        # innocence — an agent only watches one narrow slice of behaviour. Making
        # them symmetric would let any quiet agent veto a colleague that has
        # genuinely found something.
        LOW, HIGH, BENIGN_WEIGHT = 0.30, 0.50, 0.62
        if score >= HIGH:                          # assertive 'malicious'
            commit = (score - HIGH) / (1.0 - HIGH)
            m_mal = r * commit
            m_ben = 0.0
        elif score <= LOW:                         # assertive 'benign'
            commit = (LOW - score) / LOW
            m_mal = 0.0
            m_ben = r * commit * BENIGN_WEIGHT
        else:                                      # deadzone -> ignorance
            m_mal = m_ben = 0.0
        m_ign = 1.0 - (m_mal + m_ben)
        return m_mal, m_ben, max(0.0, m_ign)

    @staticmethod
    def _combine(a: Tuple[float, float, float], b: Tuple[float, float, float]):
        """Dempster's rule for two masses over {mal, ben, ign}. Returns (combined, K)."""
        am, ab, ai = a
        bm, bb, bi = b
        # conflict: mass assigned to contradictory singletons
        K = am * bb + ab * bm
        denom = 1.0 - K
        if denom <= 1e-9:
            return (0.5, 0.5, 0.0), 1.0
        m = (am * bm + am * bi + ai * bm) / denom
        bmass = (ab * bb + ab * bi + ai * bb) / denom
        i = (ai * bi) / denom
        return (m, bmass, i), K

    def reason(self) -> None:
        self._out = []
        self._tick += 1
        # merge this tick's scores into per-entity latest evidence
        for s in self._inbox:
            self._latest[s.entity][s.agent_id] = (s, self._tick)
        entities = {s.entity for s in self._inbox}
        self._inbox = []

        for entity in entities:
            fresh = {a: (sc, t) for a, (sc, t) in self._latest[entity].items()
                     if self._tick - t < self.EVIDENCE_TTL}
            self._latest[entity] = fresh
            if not fresh:
                continue
            # 1. discount each agent, then age its evidence. An agent that spoke
            #    several ticks ago still counts, but with less committed mass and
            #    correspondingly more ignorance — old news should neither drive a
            #    verdict nor manufacture conflict with what is being said now.
            masses = []
            contributors = []
            scores = []
            fresh_now: Dict[str, float] = {}
            for aid, (s, arrived) in fresh.items():
                age = self._tick - arrived
                if age == 0:
                    r = self._discount(s)
                    self.reliabilities[s.agent_id] = r
                else:
                    r = self.reliabilities.get(s.agent_id, s.confidence)
                decay = 1.0 / (1.0 + 0.6 * age)
                r_eff = r * decay
                masses.append((self._bpa(s.score, r_eff), s))
                contributors.append((s.agent_id, round(r_eff, 3), s.score))
                scores.append(s)
                if age == 0:
                    fresh_now[s.agent_id] = s.score

            # 2. Dempster-combine all agents, tracking the max pairwise conflict
            combined = masses[0][0]
            maxK = 0.0
            for m, _ in masses[1:]:
                combined, K = self._combine(combined, m)
                maxK = max(maxK, K)

            # An alarm needs TWO things, because conflict on its own is not proof
            # of subversion:
            #
            #   1. the conflict must PERSIST — during a normal escalation the
            #      domains light up a tick apart, and an agent that has not yet
            #      seen anything is entitled to say so;
            #   2. some agent must be REVERSING ITSELF about this entity — that
            #      is what the per-entity reliability discount measures. An agent
            #      that has been consistent is disagreeing honestly; an agent that
            #      said "malicious" and now insists "benign" about the same person
            #      is the signature of a poisoned sensor.
            #
            # Requiring both is what separates a subverted agent from a colleague
            # who simply has not observed the attack yet.
            if maxK >= self.tau_k:
                self._conflict_streak[entity] += 1
            else:
                self._conflict_streak[entity] = 0
            reversals = {a: self.trust[(a, entity)].reversal() for a, _w, _s in contributors}
            self.reversals[entity] = reversals

            # Persistent minority dissent. Where a clear majority of agents assert
            # one thing about a person and one agent keeps asserting the opposite,
            # tick after tick, that agent is either broken or subverted. The fusion
            # agent cannot know which — and does not need to: either way its
            # evidence should stop counting. This is the Byzantine case the base
            # study has no mechanism for.
            # Only agents that actually reported on THIS tick take part: stale
            # evidence must not be read as a live disagreement.
            asserting_mal = [a for a, sc in fresh_now.items() if sc >= 0.5]
            asserting_ben = [a for a, sc in fresh_now.items() if sc <= 0.3]
            if len(asserting_mal) >= 2 and len(asserting_ben) == 1:
                minority, majority_n = asserting_ben, len(asserting_mal)
            elif len(asserting_ben) >= 2 and len(asserting_mal) == 1:
                minority, majority_n = asserting_mal, len(asserting_ben)
            else:
                minority, majority_n = [], 0
            # Dissent only counts once the majority position is ESTABLISHED. While
            # an incident is still ramping up, agents cross their thresholds a tick
            # or two apart and the one that has not yet seen anything is simply
            # behind, not lying. Waiting for the majority to settle removes that
            # whole class of false accusation.
            if majority_n >= 2:
                self._established[entity] += 1
            else:
                self._established[entity] = 0
            established = self._established[entity] >= self.ESTABLISHED_MIN

            present = set(fresh_now)
            for a in present:
                if a in minority and majority_n >= 2 and established:
                    self._dissent[(a, entity)] += 1
                else:
                    self._dissent[(a, entity)] = 0

            dissent_now = {a: self._dissent[(a, entity)] for a in present}
            worst_agent = max(dissent_now, key=dissent_now.get) if dissent_now else None
            sustained_dissent = bool(worst_agent) and dissent_now[worst_agent] >= self.DISSENT_STREAK
            reversing = bool(worst_agent) and reversals.get(worst_agent, 0.0) >= 0.45
            self.dissent_streaks[entity] = dissent_now
            alarm = (self._conflict_streak[entity] >= self.ALARM_STREAK
                     and (sustained_dissent or reversing))

            # 3. on alarm, find the contradicting agent, discount it hard, recombine
            if alarm and len(masses) >= 2:
                belief_dir = 1.0 if combined[0] >= combined[1] else 0.0
                # the outlier is the agent whose score is furthest from the majority
                # the rogue is the agent that reversed itself; fall back to the
                # one furthest from the majority position
                if worst_agent:
                    masses.sort(key=lambda ms: ms[1].agent_id != worst_agent)
                else:
                    majority = sum(s.score for _, s in masses) / len(masses)
                    masses.sort(key=lambda ms: abs(ms[1].score - majority), reverse=True)
                rogue = masses[0][1]
                self.reliabilities[rogue.agent_id] = 0.05
                honest = [(self._bpa(s.score, self._discount_fixed(s, 0.9)), s)
                          for m, s in masses if s.agent_id != rogue.agent_id]
                if honest:
                    combined = honest[0][0]
                    for m, _ in honest[1:]:
                        combined, _K = self._combine(combined, m)
                    contributors = [(s.agent_id,
                                     0.05 if s.agent_id == rogue.agent_id else 0.9,
                                     s.score) for _, s in masses]

            belief_mal = combined[0]
            risk, tier = scoring.risk_and_tier(belief_mal, scores)
            self._out.append(Verdict(
                ts=time.time(), entity=entity, risk=risk, tier=tier,
                conflict=maxK, belief_mal=belief_mal,
                contributors=contributors, alarm=alarm,
            ))

    @staticmethod
    def _discount_fixed(s: Score, r: float) -> float:
        return r

    def act(self) -> List[Verdict]:
        return self._out
