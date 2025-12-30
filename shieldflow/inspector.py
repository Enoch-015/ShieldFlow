from dataclasses import dataclass, field
from typing import List, Optional

from .detectors import DetectionResult, DetectorSuite
from .trust import TrustDecision, TrustEngine
from .event_bus import DetectionEvent, DetectionSink


@dataclass
class InspectionDecision:
    allowed: bool
    redacted_text: Optional[str]
    detections: List[DetectionResult]
    trust: TrustDecision
    action: str = "allow"  # allow | allow_masked | block
    reason: str = ""


class Inspector:
    """Runs detectors then consults the TrustEngine to produce allow/block decisions."""

    def __init__(
        self,
        detectors: DetectorSuite,
        trust_engine: TrustEngine,
        event_sink: Optional[DetectionSink] = None,
    ) -> None:
        self.detectors = detectors
        self.trust_engine = trust_engine
        self.event_sink = event_sink

    def inspect_prompt(self, session_id: str, prompt: str, allow_masking: bool = True) -> InspectionDecision:
        detections = self.detectors.detect_prompt(prompt)
        trust_decision = self.trust_engine.apply(session_id, detections)
        allowed = not trust_decision.blocked
        redacted = None
        action = "allow"
        reason_parts = [trust_decision.reason]

        if detections:
            reason_parts.extend([d.reason for d in detections])
        if detections and allow_masking:
            redacted = self._redact(prompt, detections)
            action = "allow_masked" if allowed else "block"
        if not allowed:
            action = "block"

        decision = InspectionDecision(
            allowed=allowed,
            redacted_text=redacted,
            detections=list(detections),
            trust=trust_decision,
            action=action,
            reason="; ".join([p for p in reason_parts if p]),
        )
        self._emit_event(session_id, "prompt", decision, prompt)
        return decision

    def inspect_response(self, session_id: str, response: str) -> InspectionDecision:
        detections = self.detectors.detect_response(response)
        trust_decision = self.trust_engine.apply(session_id, detections)
        allowed = not trust_decision.blocked
        action = "allow" if allowed else "block"
        reason_parts = [trust_decision.reason] + [d.reason for d in detections]
        decision = InspectionDecision(
            allowed=allowed,
            redacted_text=None,
            detections=list(detections),
            trust=trust_decision,
            action=action,
            reason="; ".join([p for p in reason_parts if p]),
        )
        self._emit_event(session_id, "response", decision, response)
        return decision

    def _emit_event(self, session_id: str, stage: str, decision: InspectionDecision, text: str) -> None:
        if not self.event_sink:
            return
        try:
            event = DetectionEvent(
                session_id=session_id,
                stage=stage,
                action=decision.action,
                reason=decision.reason,
                trust_score=decision.trust.score,
                detections=[d.to_dict() for d in decision.detections],
                redacted_text=decision.redacted_text,
                original_text=text,
            )
            self.event_sink.send(event)
        except Exception:
            # Never block user flow on telemetry path
            return

    @staticmethod
    def _redact(text: str, detections: List[DetectionResult]) -> str:
        redacted = text
        for detection in detections:
            for match in detection.matches:
                # match may include a label prefix like label:value
                parts = match.split(":", 1)
                value = parts[1] if len(parts) == 2 else parts[0]
                if value:
                    redacted = redacted.replace(value, "[REDACTED]")
        return redacted
