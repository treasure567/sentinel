"""
agent_base.py — the abstract Agent, the perceive-reason-act cycle in code.

Every agent in the system (detection, fusion, response) is a software agent in
the sense of the course: it perceives a slice of the environment, reasons over
it against a learned or configured model, and acts by emitting a message. The
three methods below are the contract that lets the detection, fusion and
response teams build independently.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Optional


class Agent(ABC):
    agent_id: str = "agent"
    reliability: float = 1.0        # dynamic trust, adjusted by the fusion agent

    @abstractmethod
    def perceive(self, msg: Any) -> None:
        """Take a message off the bus and update internal belief/state."""
        raise NotImplementedError

    @abstractmethod
    def reason(self) -> None:
        """Score / discount / combine / choose over current beliefs."""
        raise NotImplementedError

    @abstractmethod
    def act(self) -> Optional[Any]:
        """Return a message (Score | Verdict | Action) to publish, or None."""
        raise NotImplementedError
