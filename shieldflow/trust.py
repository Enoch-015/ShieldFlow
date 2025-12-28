from dataclasses import dataclass
from typing import Dict, Iterable, Protocol

from .detectors import DetectionResult


class TrustStore(Protocol):
    def get(self, session_id: str) -> int: ...
    def set(self, session_id: str, score: int) -> None: ...


class InMemoryTrustStore:
    """Simple in-memory trust store; swap with Redis for production."""

    def __init__(self, initial: int = 100) -> None:
        self.initial = initial
        self._store: Dict[str, int] = {}

    def get(self, session_id: str) -> int:
        return self._store.get(session_id, self.initial)

    def set(self, session_id: str, score: int) -> None:
        self._store[session_id] = score


@dataclass
class TrustDecision:
    score: int
    allow_tools: bool
    blocked: bool
    reason: str = ""


class TrustEngine:
    """Maintains a rolling trust score and gating decisions."""

    def __init__(
        self,
        store: TrustStore,
        tool_threshold: int = 60,
        block_threshold: int = 30,
        min_score: int = 0,
        max_score: int = 100,
    ) -> None:
        self.store = store
        self.tool_threshold = tool_threshold
        self.block_threshold = block_threshold
        self.min_score = min_score
        self.max_score = max_score
        # Simple deltas; can be replaced with policy-driven weights.
        self._deltas = {
            "pii": -25,
            "prompt_injection": -40,
            "high_entropy": -20,
        }
        self._reward = 1

    def apply(self, session_id: str, detections: Iterable[DetectionResult]) -> TrustDecision:
        score = self.store.get(session_id)
        reason_parts = []
        for result in detections:
            delta = self._deltas.get(result.kind, 0)
            score += delta
            reason_parts.append(f"{result.kind}:{delta}")
        if not reason_parts:
            score = min(self.max_score, score + self._reward)
        score = max(self.min_score, min(self.max_score, score))
        self.store.set(session_id, score)
        allow_tools = score >= self.tool_threshold
        blocked = score < self.block_threshold
        reason = ",".join(reason_parts) if reason_parts else "clean"
        return TrustDecision(score=score, allow_tools=allow_tools, blocked=blocked, reason=reason)
