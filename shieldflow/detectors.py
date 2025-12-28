import math
import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence


@dataclass
class DetectionResult:
    kind: str
    confidence: float
    matches: Sequence[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "confidence": self.confidence,
            "matches": list(self.matches),
            "reason": self.reason,
        }


@dataclass
class DetectorConfig:
    pii_confidence: float = 0.6
    injection_confidence: float = 0.6
    entropy_threshold: float = 4.0  # bits per char
    entropy_min_length: int = 64


class DetectorSuite:
    """Collection of lightweight detectors for prompts and responses."""

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()
        # Quick patterns to start; swap for ML detectors later.
        self._pii_patterns = {
            "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
            "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        }
        self._injection_markers = [
            "ignore previous",
            "disregard above",
            "you are now",
            "bypass",
            "override",
            "system prompt",
            "forget instructions",
        ]

    def detect_prompt(self, text: str) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        pii = self._detect_pii(text)
        if pii:
            results.append(pii)
        inj = self._detect_injection(text)
        if inj:
            results.append(inj)
        return results

    def detect_response(self, text: str) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        entropy = self._detect_entropy(text)
        if entropy:
            results.append(entropy)
        return results

    def _detect_pii(self, text: str) -> Optional[DetectionResult]:
        matches = []
        for label, pattern in self._pii_patterns.items():
            found = pattern.findall(text)
            if found:
                matches.extend([f"{label}:{m}" for m in found])
        if not matches:
            return None
        confidence = min(1.0, 0.5 + 0.05 * len(matches))
        confidence = max(confidence, self.config.pii_confidence)
        return DetectionResult(
            kind="pii",
            confidence=confidence,
            matches=matches,
            reason="PII-like patterns found",
        )

    def _detect_injection(self, text: str) -> Optional[DetectionResult]:
        lowered = text.lower()
        hits = [marker for marker in self._injection_markers if marker in lowered]
        if not hits:
            return None
        confidence = min(1.0, 0.4 + 0.1 * len(hits))
        confidence = max(confidence, self.config.injection_confidence)
        return DetectionResult(
            kind="prompt_injection",
            confidence=confidence,
            matches=hits,
            reason="Prompt injection markers detected",
        )

    def _detect_entropy(self, text: str) -> Optional[DetectionResult]:
        if len(text) < self.config.entropy_min_length:
            return None
        entropy = self._shannon_entropy(text)
        if entropy < self.config.entropy_threshold:
            return None
        confidence = min(1.0, (entropy - self.config.entropy_threshold) / 2.0 + 0.5)
        return DetectionResult(
            kind="high_entropy",
            confidence=confidence,
            matches=[f"entropy={entropy:.2f}"],
            reason="Response entropy spike suggests exfiltration",
        )

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        # Simple entropy calculation over characters.
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
