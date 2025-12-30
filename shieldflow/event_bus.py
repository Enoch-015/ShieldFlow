import json
import logging
import os
from dataclasses import dataclass, asdict
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)


@dataclass
class DetectionEvent:
    session_id: str
    stage: str  # prompt | response
    action: str
    reason: str
    trust_score: float
    detections: list
    redacted_text: Optional[str]
    original_text: Optional[str]

    def to_json(self) -> str:
        return json.dumps(asdict(self))


class DetectionSink(Protocol):
    def send(self, event: DetectionEvent) -> None: ...


class InMemorySink:
    def __init__(self) -> None:
        self.events: list[DetectionEvent] = []

    def send(self, event: DetectionEvent) -> None:
        self.events.append(event)


class KafkaDetectionSink:
    """Kafka sink for detection events.

    Uses kafka-python if available. Send failures are logged but do not raise.
    """

    def __init__(self, topic: str, bootstrap_servers: str, **producer_kwargs: Any) -> None:
        try:
            from kafka import KafkaProducer  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise ImportError("kafka-python is required for KafkaDetectionSink") from exc
        self.topic = topic
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: v.encode("utf-8"),
            **producer_kwargs,
        )

    def send(self, event: DetectionEvent) -> None:
        try:
            self.producer.send(self.topic, event.to_json())
        except Exception as exc:  # pragma: no cover - transport failure
            logger.warning("Failed to emit detection event to Kafka: %s", exc)


def build_kafka_sink_from_env() -> Optional[KafkaDetectionSink]:
    """Best-effort Kafka sink based on env vars.

    Reads SHIELDFLOW_KAFKA_BOOTSTRAP (or KAFKA_BOOTSTRAP_SERVERS) and
    SHIELDFLOW_KAFKA_TOPIC. Returns None if misconfigured or kafka-python
    is unavailable.
    """

    bootstrap = os.getenv("SHIELDFLOW_KAFKA_BOOTSTRAP") or os.getenv("KAFKA_BOOTSTRAP_SERVERS")
    if not bootstrap:
        return None
    topic = os.getenv("SHIELDFLOW_KAFKA_TOPIC", "shieldflow.detections")
    try:
        return KafkaDetectionSink(topic=topic, bootstrap_servers=bootstrap)
    except Exception as exc:  # pragma: no cover - optional path
        logger.warning("Kafka sink disabled: %s", exc)
        return None