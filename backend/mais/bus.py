"""
bus.py — a minimal publish/subscribe message bus.

The report specifies an asynchronous message bus; for the prototype this is an
in-process synchronous pub/sub with the same publish/subscribe surface, so a
real broker (Kafka, RabbitMQ, NATS) could be swapped in later without changing
any agent. No component ever calls another directly: they communicate only by
publishing typed messages (see contracts.py) onto named topics.
"""
from __future__ import annotations
from collections import defaultdict
from typing import Callable, Any, Dict, List


class Bus:
    def __init__(self) -> None:
        self._subs: Dict[str, List[Callable[[Any], None]]] = defaultdict(list)

    def subscribe(self, topic: str, handler: Callable[[Any], None]) -> None:
        """Register a handler(msg) to be invoked for every message on `topic`."""
        self._subs[topic].append(handler)

    def publish(self, topic: str, msg: Any) -> None:
        """Deliver `msg` to every subscriber of `topic`, in registration order."""
        for handler in list(self._subs.get(topic, ())):
            handler(msg)
